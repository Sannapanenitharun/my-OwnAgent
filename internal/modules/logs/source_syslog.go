package logs

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// syslogListener accepts log messages over TCP and UDP.
//
// IT IS OFF BY DEFAULT and stays off until an operator sets an address, which
// is the same posture the StatsD receiver takes and for a stronger reason: a
// syslog port accepts unauthenticated writes into the log pipeline from anyone
// who can reach it. On a host whose security group is permissive, binding
// 0.0.0.0 would publish an open ingest endpoint that anyone can fill with
// anything. Bind loopback unless the senders are genuinely remote, and put a
// firewall in front of it when they are.
//
// WHY IT LIVES BEHIND THE PULL INTERFACE. Every other reader here is asked for
// records on a schedule; this one receives them whenever a sender feels like
// it. The listener goroutines write into a bounded queue and Read drains it,
// so the push-shaped source fits the pull-shaped interface without either side
// having to know about the other. The queue is bounded because the alternative
// is letting a remote sender decide how much memory this process uses.
type syslogListener struct {
	// life serialises start against Close. It is separate from mu because
	// Close must wait on the serving goroutines, and those goroutines take mu
	// to enqueue -- holding mu across that wait would deadlock. Without this,
	// Stop racing a collection cycle could call wg.Wait() while start() was
	// still adding to the same WaitGroup.
	life sync.Mutex

	mu      sync.Mutex
	addr    string // the address currently bound, empty when stopped
	queue   []Record
	dropped int64

	udp   net.PacketConn
	tcp   net.Listener
	conns map[net.Conn]struct{}

	stop chan struct{}
	wg   sync.WaitGroup
}

const (
	// maxSyslogQueue bounds records held between collection cycles. At the
	// default two-second interval this absorbs a burst of a few thousand
	// messages per second; beyond it, the oldest are dropped and counted,
	// because a queue that grows without limit turns a noisy sender into an
	// outage.
	maxSyslogQueue = 8192

	// maxSyslogDatagram is the largest UDP payload accepted. RFC 5426 sets
	// 65535 as the ceiling and most senders stay under 2 KiB.
	maxSyslogDatagram = 64 << 10

	// maxSyslogLine bounds one TCP-framed message.
	maxSyslogLine = 64 << 10

	// maxSyslogConns bounds concurrent TCP connections, so a sender that
	// opens sockets and never writes cannot exhaust descriptors.
	maxSyslogConns = 128
)

func newSyslogListener() *syslogListener {
	return &syslogListener{conns: map[net.Conn]struct{}{}}
}

// Read drains what has arrived since the last cycle, starting or stopping the
// listeners if the configured address has changed.
func (l *syslogListener) Read(_ context.Context, s Settings) ([]Record, error) {
	want := strings.TrimSpace(s.SyslogListen)
	l.mu.Lock()
	current := l.addr
	l.mu.Unlock()

	if want != current {
		l.Close()
		if want != "" {
			if err := l.start(want, s); err != nil {
				return nil, err
			}
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.queue) == 0 {
		return nil, nil
	}
	n := len(l.queue)
	if n > s.MaxBatch {
		n = s.MaxBatch
	}
	out := l.queue[:n:n]
	l.queue = append([]Record(nil), l.queue[n:]...)
	return out, nil
}

func (l *syslogListener) start(addr string, s Settings) error {
	l.life.Lock()
	defer l.life.Unlock()

	proto := s.SyslogProtocol
	if proto == "" {
		proto = SyslogBoth
	}
	stop := make(chan struct{})

	l.mu.Lock()
	l.addr = addr
	l.stop = stop
	l.mu.Unlock()

	if proto == SyslogUDP || proto == SyslogBoth {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			l.closeLocked()
			return err
		}
		l.mu.Lock()
		l.udp = pc
		l.mu.Unlock()
		l.wg.Add(1)
		go l.serveUDP(pc, stop)
	}
	if proto == SyslogTCP || proto == SyslogBoth {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			l.closeLocked()
			return err
		}
		l.mu.Lock()
		l.tcp = ln
		l.mu.Unlock()
		l.wg.Add(1)
		go l.serveTCP(ln, stop)
	}
	return nil
}

func (l *syslogListener) serveUDP(pc net.PacketConn, stop <-chan struct{}) {
	defer l.wg.Done()
	buf := make([]byte, maxSyslogDatagram)
	for {
		select {
		case <-stop:
			return
		default:
		}
		// A deadline rather than a blocking read, so Close is noticed even
		// when nothing is sending.
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := pc.ReadFrom(buf)
		if n > 0 {
			// One datagram is exactly one message: UDP syslog has no framing
			// because it does not need any.
			l.enqueue(string(buf[:n]), remote)
		}
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
	}
}

func (l *syslogListener) serveTCP(ln net.Listener, stop <-chan struct{}) {
	defer l.wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
		}
		if tl, ok := ln.(*net.TCPListener); ok {
			_ = tl.SetDeadline(time.Now().Add(time.Second))
		}
		conn, err := ln.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		l.mu.Lock()
		over := len(l.conns) >= maxSyslogConns
		if !over {
			l.conns[conn] = struct{}{}
		}
		l.mu.Unlock()
		if over {
			conn.Close()
			continue
		}
		l.wg.Add(1)
		go l.serveConn(conn, stop)
	}
}

// serveConn reads one TCP connection.
//
// RFC 6587 defines two framings and senders use both. Octet-counting prefixes
// each message with its length and a space; non-transparent framing just
// separates messages with a newline. Which one is in use is decided per
// message by looking at whether it starts with a digit, because a syslog
// message always starts with "<".
func (l *syslogListener) serveConn(conn net.Conn, stop <-chan struct{}) {
	defer l.wg.Done()
	defer func() {
		conn.Close()
		l.mu.Lock()
		delete(l.conns, conn)
		l.mu.Unlock()
	}()

	r := bufio.NewReaderSize(conn, 8<<10)
	for {
		select {
		case <-stop:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		c, err := r.ReadByte()
		if err != nil {
			return
		}
		if c >= '0' && c <= '9' {
			if err := r.UnreadByte(); err != nil {
				return
			}
			if !l.readOctetCounted(r, conn) {
				return
			}
			continue
		}
		if err := r.UnreadByte(); err != nil {
			return
		}
		line, err := readLimitedLine(r, maxSyslogLine)
		if line != "" {
			l.enqueue(line, conn.RemoteAddr())
		}
		if err != nil {
			return
		}
	}
}

// readOctetCounted reads "LENGTH SP MESSAGE".
func (l *syslogListener) readOctetCounted(r *bufio.Reader, conn net.Conn) bool {
	var digits []byte
	for len(digits) < 10 {
		c, err := r.ReadByte()
		if err != nil {
			return false
		}
		if c == ' ' {
			break
		}
		if c < '0' || c > '9' {
			// Not a length after all. The stream is out of sync and there is
			// no safe way to resynchronise, so the connection ends rather
			// than the parser guessing.
			return false
		}
		digits = append(digits, c)
	}
	n, err := strconv.Atoi(string(digits))
	// A sender declaring a length this process must then allocate is exactly
	// the input that must not be trusted.
	if err != nil || n <= 0 || n > maxSyslogLine {
		return false
	}
	buf := make([]byte, n)
	read := 0
	for read < n {
		m, err := r.Read(buf[read:])
		read += m
		if err != nil {
			return false
		}
	}
	l.enqueue(string(buf), conn.RemoteAddr())
	return true
}

// readLimitedLine reads up to a newline without letting a sender that never
// sends one grow the buffer indefinitely.
func readLimitedLine(r *bufio.Reader, limit int) (string, error) {
	var b strings.Builder
	for b.Len() < limit {
		c, err := r.ReadByte()
		if err != nil {
			return strings.TrimRight(b.String(), "\r"), err
		}
		if c == '\n' {
			return strings.TrimRight(b.String(), "\r"), nil
		}
		b.WriteByte(c)
	}
	return strings.TrimRight(b.String(), "\r"), nil
}

// enqueue parses one wire message and queues it, dropping the oldest when the
// queue is full.
func (l *syslogListener) enqueue(raw string, remote net.Addr) {
	raw = strings.TrimRight(raw, "\x00\r\n")
	if strings.TrimSpace(raw) == "" {
		return
	}
	msg := parseSyslog(raw)

	rec := Record{
		Body:     msg.Message,
		Source:   SourceSyslog,
		Process:  msg.AppName,
		PID:      msg.PID,
		Hostname: msg.Hostname,
	}
	if msg.HasPriority {
		rec.Priority, rec.HasPriority = msg.Priority, true
	}
	// The sender's own hostname field is whatever it chose to claim. The peer
	// address is what the network observed, so when they disagree -- or when
	// the sender omitted one -- the observed value is the one worth keeping.
	if rec.Hostname == "" && remote != nil {
		if host, _, err := net.SplitHostPort(remote.String()); err == nil {
			rec.Hostname = host
		} else {
			rec.Hostname = remote.String()
		}
	}
	// Process attribution requires both halves, as everywhere else here: a PID
	// with no name is a number nobody can look up.
	if rec.Process == "" {
		rec.PID = 0
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.queue) >= maxSyslogQueue {
		// Drop the oldest. A syslog relay's backlog is stale by definition,
		// and keeping the newest is what an operator watching a live incident
		// actually wants.
		l.queue = l.queue[1:]
		l.dropped++
	}
	l.queue = append(l.queue, rec)
}

// Dropped reports how many messages were discarded for queue pressure.
func (l *syslogListener) Dropped() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dropped
}

// Close stops the listeners and releases the sockets.
func (l *syslogListener) Close() {
	l.life.Lock()
	defer l.life.Unlock()
	l.closeLocked()
}

// closeLocked is Close with the lifecycle lock already held, so start can use
// it on its own error paths without deadlocking against itself.
func (l *syslogListener) closeLocked() {
	l.mu.Lock()
	stop := l.stop
	udp, tcp := l.udp, l.tcp
	conns := make([]net.Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.stop, l.udp, l.tcp, l.addr = nil, nil, nil, ""
	l.conns = map[net.Conn]struct{}{}
	l.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	if udp != nil {
		udp.Close()
	}
	if tcp != nil {
		tcp.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	l.wg.Wait()
}
