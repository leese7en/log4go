package log4go

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	stdLog "log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type severity int32

const (
	infoLog severity = iota
	debugLog
	warningLog
	errorLog
	fatalLog
	numSeverity = 5
)

const severityChar = "IDWEF"

var severityName = []string{
	infoLog:    "INFO",
	debugLog:   "DEBUG",
	warningLog: "WARNING",
	errorLog:   "ERROR",
	fatalLog:   "FATAL",
}

func (s *severity) get() severity {
	return severity(atomic.LoadInt32((*int32)(s)))
}

func (s *severity) set(val severity) {
	atomic.StoreInt32((*int32)(s), int32(val))
}

func (s *severity) String() string {
	return strconv.FormatInt(int64(*s), 10)
}

func (s *severity) Get() interface{} {
	return *s
}

func (s *severity) SetConsole(value string) error {
	var threshold severity

	if v, ok := severityByName(value); ok {
		threshold = v
	} else {
		v, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		threshold = severity(v)
	}
	logging.consoleLevel.set(threshold)
	return nil
}

func (s *severity) SetFile(value string) error {
	var threshold severity

	if v, ok := severityByName(value); ok {
		threshold = v
	} else {
		v, err := strconv.Atoi(value)
		if err != nil {
			return err
		}
		threshold = severity(v)
	}
	logging.fileLevel.set(threshold)
	return nil
}

func severityByName(s string) (severity, bool) {
	s = strings.ToUpper(s)
	for i, name := range severityName {
		if name == s {
			return severity(i), true
		}
	}
	return 0, false
}

type OutputStats struct {
	lines int64
	bytes int64
}

func (s *OutputStats) Lines() int64 {
	return atomic.LoadInt64(&s.lines)
}

func (s *OutputStats) Bytes() int64 {
	return atomic.LoadInt64(&s.bytes)
}

var Stats struct {
	Info, Debug, Warning, Error OutputStats
}

var severityStats = [numSeverity]*OutputStats{
	infoLog:    &Stats.Info,
	debugLog:   &Stats.Debug,
	warningLog: &Stats.Warning,
	errorLog:   &Stats.Error,
}

type Level int32

func (l *Level) get() Level {
	return Level(atomic.LoadInt32((*int32)(l)))
}

func (l *Level) set(val Level) {
	atomic.StoreInt32((*int32)(l), int32(val))
}

func (l *Level) String() string {
	return strconv.FormatInt(int64(*l), 10)
}

func (l *Level) Get() interface{} {
	return *l
}

func (l *Level) Set(value string) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	logging.setVState(Level(v), logging.vmodule.filter, false)
	return nil
}

type moduleSpec struct {
	filter []modulePat
}

type modulePat struct {
	pattern string
	literal bool
	level   Level
}

func (m *modulePat) match(file string) bool {
	if m.literal {
		return file == m.pattern
	}
	match, _ := filepath.Match(m.pattern, file)
	return match
}

func (m *moduleSpec) String() string {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	var b bytes.Buffer
	for i, f := range m.filter {
		if i > 0 {
			b.WriteRune(',')
		}
		fmt.Fprintf(&b, "%s=%d", f.pattern, f.level)
	}
	return b.String()
}

func (m *moduleSpec) Get() interface{} {
	return nil
}

var errVmoduleSyntax = errors.New("syntax error: expect comma-separated list of filename=N")

func (m *moduleSpec) Set(value string) error {
	var filter []modulePat
	for _, pat := range strings.Split(value, ",") {
		if len(pat) == 0 {
			continue
		}
		patLev := strings.Split(pat, "=")
		if len(patLev) != 2 || len(patLev[0]) == 0 || len(patLev[1]) == 0 {
			return errVmoduleSyntax
		}
		pattern := patLev[0]
		v, err := strconv.Atoi(patLev[1])
		if err != nil {
			return errors.New("syntax error: expect comma-separated list of filename=N")
		}
		if v < 0 {
			return errors.New("negative value for vmodule level")
		}
		if v == 0 {
			continue
		}
		filter = append(filter, modulePat{pattern, isLiteral(pattern), Level(v)})
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return nil
}

func isLiteral(pattern string) bool {
	return !strings.ContainsAny(pattern, `\*?[]`)
}

type traceLocation struct {
	file string
	line int
}

func (t *traceLocation) isSet() bool {
	return t.line > 0
}

func (t *traceLocation) match(file string, line int) bool {
	if t.line != line {
		return false
	}
	if i := strings.LastIndex(file, "/"); i >= 0 {
		file = file[i+1:]
	}
	return t.file == file
}

func (t *traceLocation) String() string {
	logging.mu.Lock()
	defer logging.mu.Unlock()
	return fmt.Sprintf("%s:%d", t.file, t.line)
}

func (t *traceLocation) Get() interface{} {
	return nil
}

var errTraceSyntax = errors.New("syntax error: expect file.go:234")

func (t *traceLocation) Set(value string) error {
	if value == "" {
		// Unset.
		t.line = 0
		t.file = ""
	}
	fields := strings.Split(value, ":")
	if len(fields) != 2 {
		return errTraceSyntax
	}
	file, line := fields[0], fields[1]
	if !strings.Contains(file, ".") {
		return errTraceSyntax
	}
	v, err := strconv.Atoi(line)
	if err != nil {
		return errTraceSyntax
	}
	if v <= 0 {
		return errors.New("negative or zero value for level")
	}
	logging.mu.Lock()
	defer logging.mu.Unlock()
	t.line = v
	t.file = file
	return nil
}

type flushSyncWriter interface {
	Flush() error
	Sync() error
	io.Writer
}

var logDirs []string

func createLogDir() {
	if logging.logDir != "" {
		err := os.MkdirAll(logging.logDir, 0777)
		if err != nil {
			fmt.Println("日志目录失败")
		}
	} else {
		logging.logDir = LogDir
		err := os.MkdirAll(logging.logDir, 0777)
		if err != nil {
			fmt.Println("日志目录失败")
		}
	}
}

var (
	pid      = os.Getpid()
	program  = filepath.Base(os.Args[0])
	host     = "unknownhost"
	userName = "unknownuser"
)

func shortHostname(hostname string) string {
	if i := strings.Index(hostname, "."); i >= 0 {
		return hostname[:i]
	}
	return hostname
}

func logName(t time.Time) (name, link string) {
	name = fmt.Sprintf("%04d-%02d-%02d-%02d-%02d-%02d %d.log",
		t.Year(),
		t.Month(),
		t.Day(),
		t.Hour(),
		t.Minute(),
		t.Second(),
		pid)
	return name, program
}

var onceLogDirs sync.Once

func create(t time.Time) (f *os.File, filename string, err error) {
	onceLogDirs.Do(createLogDir)
	name, link := logName(t)
	var lastErr error
	dir := logging.logDir
	fname := filepath.Join(dir, name)
	f, err = os.Create(fname)
	if err == nil {
		symlink := filepath.Join(dir, link)
		os.Remove(symlink)
		os.Symlink(name, symlink)
		return f, fname, nil
	}
	lastErr = err
	return nil, "", fmt.Errorf("log: cannot create log: %v", lastErr)
}

const (
	ConsoleOut   bool     = true
	FileOut      bool     = true
	ConsoleLevel severity = 0
	FileLevel    severity = 0
	MaxSize      uint64   = 1024 * 1024 * 100
	FileType     string   = "size"
	LogDir       string   = "./logs"
	Strategy     string   = "yyyy-mm-dd"
)

func init() {
	h, err := os.Hostname()
	if err == nil {
		host = shortHostname(h)
	}

	current, err := user.Current()
	if err == nil {
		userName = current.Username
	}
	userName = strings.Replace(userName, `\`, "_", -1)
	conf, err := SetConfig("./config/log4go.properties")
	if err != nil {
		logging.consoleOut = ConsoleOut
		logging.consoleLevel = ConsoleLevel
		logging.fileOut = FileOut
		logging.fileLevel = FileLevel
		logging.logDir = LogDir
		logging.logType = FileType
		logging.maxsize = MaxSize
	} else {
		confList, _ := conf.GetConfig()
		logging.consoleOut = ConsoleOut
		logging.consoleLevel = ConsoleLevel
		logging.fileOut = FileOut
		logging.fileLevel = FileLevel
		logging.logDir = LogDir
		logging.logType = FileType
		logging.maxsize = MaxSize
		for key, v := range confList {
			switch key {
			case "log4go.console":
				if strings.ToUpper(v) == "TRUE" {
					logging.consoleOut = true
				} else {
					logging.consoleOut = false
				}
			case "log4go.consoleLevel":
				v = strings.ToUpper(v)
				if v == "DEBUG" {
					logging.consoleLevel = severity(1)
				} else if v == "WARN" {
					logging.consoleLevel = severity(2)
				} else if v == "ERROR" {
					logging.consoleLevel = severity(3)
				} else if v == "FATAL" {
					logging.consoleLevel = severity(4)
				} else {
					logging.consoleLevel = severity(0)
				}
			case "log4go.file":
				if strings.ToUpper(v) == "TRUE" {
					logging.fileOut = true
				} else {
					logging.fileOut = false
				}
			case "log4go.fileLevel":
				v = strings.ToUpper(v)
				if v == "DEBUG" {
					logging.fileLevel = severity(1)
				} else if v == "WARN" {
					logging.fileLevel = severity(2)
				} else if v == "ERROR" {
					logging.fileLevel = severity(3)
				} else if v == "FATAL" {
					logging.fileLevel = severity(4)
				} else {
					logging.fileLevel = severity(0)
				}

			case "log4go.file.path":
				logging.logDir = v
			case "log4go.file.type":
				v = strings.ToLower(v)
				if v == "size" || v == "date" {
				} else {
					v = "default"
				}
				logging.logType = v
			case "log4go.file.strategy":
				strategy, logName := formatLogName(v)
				logging.strategy = strategy
				logging.logName = logName
			case "log4go.file.maxsize":
				i, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					i = 100 * 1024
				}
				i = 1024 * i
				logging.maxsize = uint64(i)
			default:
			}
		}
	}
	flag.Var(&logging.vmodule, "log4govmodule", "comma-separated list of pattern=N settings for file-filtered logging")
	flag.Var(&logging.traceLocation, "log4go_log_backtrace_at", "when logging hits line file:N, emit a stack trace")
	go logging.flushDaemon()
}

func formatLogName(strategy string) (string, string) {
	var format string
	switch strategy {
	case "yyyy-mm-dd hh:MM":
		format = "2016-01-02 15:04"
	case "yyyy-mm-dd hh":
		format = "2016--01-02 15"
	case "yyyy-mm-dd":
		format = "2016-01-02"
	case "yyyy-mm":
		format = "2016-01"
	case "yyyy":
		format = "2016"
	default:
		format = "2016-01-02"
		strategy = "yyyy-mm-dd"
	}
	fileName := time.Now().Format(format)
	return strategy, fileName
}

func Flush() {
	logging.lockAndFlushAll()
}

type loggingT struct {
	consoleOut    bool
	fileOut       bool
	consoleLevel  severity
	fileLevel     severity
	logDir        string
	logType       string
	logName       string
	strategy      string
	maxsize       uint64
	freeList      *buffer
	freeListMu    sync.Mutex
	mu            sync.Mutex
	file          flushSyncWriter
	pcs           [1]uintptr
	vmap          map[uintptr]Level
	filterLength  int32
	traceLocation traceLocation
	vmodule       moduleSpec
}

type buffer struct {
	bytes.Buffer
	tmp  [64]byte
	next *buffer
}

var logging loggingT

func (l *loggingT) setVState(verbosity Level, filter []modulePat, setFilter bool) {
	atomic.StoreInt32(&logging.filterLength, 0)

	if setFilter {
		logging.vmodule.filter = filter
		logging.vmap = make(map[uintptr]Level)
	}
	atomic.StoreInt32(&logging.filterLength, int32(len(filter)))
}
func (l *loggingT) getBuffer() *buffer {
	l.freeListMu.Lock()
	b := l.freeList
	if b != nil {
		l.freeList = b.next
	}
	l.freeListMu.Unlock()
	if b == nil {
		b = new(buffer)
	} else {
		b.next = nil
		b.Reset()
	}
	return b
}

func (l *loggingT) putBuffer(b *buffer) {
	if b.Len() >= 256 {
		return
	}
	l.freeListMu.Lock()
	b.next = l.freeList
	l.freeList = b
	l.freeListMu.Unlock()
}

var timeNow = time.Now

func (l *loggingT) header(s severity, depth int) (*buffer, string, int) {
	_, file, line, ok := runtime.Caller(3 + depth)
	if !ok {
		file = "???"
		line = 1
	} else {
		slash := strings.LastIndex(file, "/")
		if slash >= 0 {
			file = file[slash+1:]
		}
	}
	return l.formatHeader(s, file, line), file, line
}

func (l *loggingT) formatHeader(s severity, file string, line int) *buffer {
	now := timeNow()
	if line < 0 {
		line = 0
	}
	if s > fatalLog {
		s = infoLog
	}
	buf := l.getBuffer()

	year, month, day := now.Date()
	hour, minute, second := now.Clock()
	// Lmmdd hh:mm:ss.uuuuuu threadid file:line]
	buf.tmp[0] = severityChar[s]
	buf.tmp[1] = ' '
	buf.nDigits(4, 2, year, ' ')
	buf.twoDigits(6, int(month))
	buf.twoDigits(8, day)
	buf.tmp[10] = ' '
	buf.twoDigits(11, hour)
	buf.tmp[13] = ':'
	buf.twoDigits(14, minute)
	buf.tmp[16] = ':'
	buf.twoDigits(17, second)
	buf.tmp[19] = '.'
	buf.nDigits(6, 20, now.Nanosecond()/1000, '0')
	buf.tmp[26] = ' '
	buf.nDigits(6, 27, pid, ' ')
	buf.tmp[33] = ' '
	buf.Write(buf.tmp[:34])
	buf.WriteString(file)
	buf.tmp[0] = ':'
	n := buf.someDigits(1, line)
	buf.tmp[n+1] = ']'
	buf.tmp[n+2] = ' '
	buf.Write(buf.tmp[:n+3])
	return buf
}

const digits = "0123456789"

func (buf *buffer) twoDigits(i, d int) {
	buf.tmp[i+1] = digits[d%10]
	d /= 10
	buf.tmp[i] = digits[d%10]
}

func (buf *buffer) nDigits(n, i, d int, pad byte) {
	j := n - 1
	for ; j >= 0 && d > 0; j-- {
		buf.tmp[i+j] = digits[d%10]
		d /= 10
	}
	for ; j >= 0; j-- {
		buf.tmp[i+j] = pad
	}
}

func (buf *buffer) someDigits(i, d int) int {
	j := len(buf.tmp)
	for {
		j--
		buf.tmp[j] = digits[d%10]
		d /= 10
		if d == 0 {
			break
		}
	}
	return copy(buf.tmp[i:], buf.tmp[j:])
}

func (l *loggingT) println(s severity, args ...interface{}) {
	buf, file, line := l.header(s, 0)
	fmt.Fprintln(buf, args...)
	l.output(s, buf, file, line, false)
}

func (l *loggingT) print(s severity, args ...interface{}) {
	l.printDepth(s, 1, args...)
}

func (l *loggingT) printDepth(s severity, depth int, args ...interface{}) {
	buf, file, line := l.header(s, depth)
	fmt.Fprint(buf, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, false)
}

func (l *loggingT) printf(s severity, format string, args ...interface{}) {
	buf, file, line := l.header(s, 0)
	fmt.Fprintf(buf, format, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, false)
}

func (l *loggingT) printWithFileLine(s severity, file string, line int, alsoToStderr bool, args ...interface{}) {
	buf := l.formatHeader(s, file, line)
	fmt.Fprint(buf, args...)
	if buf.Bytes()[buf.Len()-1] != '\n' {
		buf.WriteByte('\n')
	}
	l.output(s, buf, file, line, alsoToStderr)
}

func (l *loggingT) output(s severity, buf *buffer, file string, line int, alsoToStderr bool) {
	l.mu.Lock()
	if l.traceLocation.isSet() {
		if l.traceLocation.match(file, line) {
			buf.Write(stacks(false))
		}
	}
	data := buf.Bytes()

	if alsoToStderr || (l.consoleOut && s >= l.consoleLevel.get()) {
		os.Stderr.Write(data)
	}
	if l.file == nil {
		if err := l.createFiles(); err != nil {
			os.Stderr.Write(data)
			l.exit(err)
		}
	}
	if l.fileOut && s >= l.fileLevel.get() {
		l.file.Write(data)
	}
	if s == fatalLog {
		if atomic.LoadUint32(&fatalNoStacks) > 0 {
			l.mu.Unlock()
			timeoutFlush(10 * time.Second)
			os.Exit(1)
		}
		trace := stacks(true)
		logExitFunc = func(error) {}
		if f := l.file; f != nil {
			f.Write(trace)
		}
		l.mu.Unlock()
		timeoutFlush(10 * time.Second)
		os.Exit(255)
	}
	l.putBuffer(buf)
	l.mu.Unlock()
	if stats := severityStats[s]; stats != nil {
		atomic.AddInt64(&stats.lines, 1)
		atomic.AddInt64(&stats.bytes, int64(len(data)))
	}
}

func timeoutFlush(timeout time.Duration) {
	done := make(chan bool, 1)
	go func() {
		Flush()
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		fmt.Fprintln(os.Stderr, "glog: Flush took longer than", timeout)
	}
}

func stacks(all bool) []byte {
	n := 10000
	if all {
		n = 100000
	}
	var trace []byte
	for i := 0; i < 5; i++ {
		trace = make([]byte, n)
		nbytes := runtime.Stack(trace, all)
		if nbytes < len(trace) {
			return trace[:nbytes]
		}
		n *= 2
	}
	return trace
}

var logExitFunc func(error)

func (l *loggingT) exit(err error) {
	fmt.Fprintf(os.Stderr, "log: exiting because of error: %s\n", err)
	if logExitFunc != nil {
		logExitFunc(err)
		return
	}
	l.flushAll()
	os.Exit(2)
}

type syncBuffer struct {
	logger *loggingT
	*bufio.Writer
	file   *os.File
	sev    severity
	nbytes uint64
}

func (sb *syncBuffer) Sync() error {
	return sb.file.Sync()
}

func (sb *syncBuffer) Write(p []byte) (n int, err error) {
	fileType := logging.logType
	switch fileType {
	case "date":
		_, nameTemp := formatLogName(logging.strategy)
		if nameTemp != logging.logName {
			if err := sb.rotateFile(time.Now()); err != nil {
				sb.logger.exit(err)
			}
			logging.logName = nameTemp
		}
	case "size":
		if sb.nbytes+uint64(len(p)) >= logging.maxsize {
			if err := sb.rotateFile(time.Now()); err != nil {
				sb.logger.exit(err)
			}
		}
	default:
		if sb.nbytes+uint64(len(p)) >= MaxSize {
			if err := sb.rotateFile(time.Now()); err != nil {
				sb.logger.exit(err)
			}
		}
	}
	n, err = sb.Writer.Write(p)
	sb.nbytes += uint64(n)
	if err != nil {
		sb.logger.exit(err)
	}
	return
}

func (sb *syncBuffer) rotateFile(now time.Time) error {
	if sb.file != nil {
		sb.Flush()
		sb.file.Close()
	}
	var err error
	sb.file, _, err = create(now)
	sb.nbytes = 0
	if err != nil {
		return err
	}
	sb.Writer = bufio.NewWriterSize(sb.file, bufferSize)
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "Log file created at: %s\n", now.Format("2006/01/02 15:04:05"))
	fmt.Fprintf(&buf, "Running on machine: %s\n", host)
	fmt.Fprintf(&buf, "Binary: Built with %s %s for %s/%s\n", runtime.Compiler, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&buf, "Log line format: [IWEF]mmdd hh:mm:ss.uuuuuu threadid file:line] msg\n")
	n, err := sb.file.Write(buf.Bytes())
	sb.nbytes += uint64(n)
	return err
}

const bufferSize = 256 * 1024

func (l *loggingT) createFiles() error {
	now := time.Now()
	sb := &syncBuffer{logger: l}
	if err := sb.rotateFile(now); err != nil {
		return err
	}
	l.file = sb
	return nil
}

const flushInterval = 30 * time.Second

func (l *loggingT) flushDaemon() {
	for _ = range time.NewTicker(flushInterval).C {
		l.lockAndFlushAll()
	}
}

func (l *loggingT) lockAndFlushAll() {
	l.mu.Lock()
	l.flushAll()
	l.mu.Unlock()
}

func (l *loggingT) flushAll() {
	file := l.file
	if file != nil {
		file.Flush()
		file.Sync()
	}
}

func CopyStandardLogTo(name string) {
	sev, ok := severityByName(name)
	if !ok {
		panic(fmt.Sprintf("log.CopyStandardLogTo(%q): unrecognized severity name", name))
	}
	stdLog.SetFlags(stdLog.Lshortfile)
	stdLog.SetOutput(logBridge(sev))
}

type logBridge severity

func (lb logBridge) Write(b []byte) (n int, err error) {
	var (
		file = "???"
		line = 1
		text string
	)
	if parts := bytes.SplitN(b, []byte{':'}, 3); len(parts) != 3 || len(parts[0]) < 1 || len(parts[2]) < 1 {
		text = fmt.Sprintf("bad log format: %s", b)
	} else {
		file = string(parts[0])
		text = string(parts[2][1:])
		line, err = strconv.Atoi(string(parts[1]))
		if err != nil {
			text = fmt.Sprintf("bad line number: %s", b)
			line = 1
		}
	}
	logging.printWithFileLine(severity(lb), file, line, true, text)
	return len(b), nil
}

func (l *loggingT) setV(pc uintptr) Level {
	fn := runtime.FuncForPC(pc)
	file, _ := fn.FileLine(pc)
	if strings.HasSuffix(file, ".go") {
		file = file[:len(file)-3]
	}
	if slash := strings.LastIndex(file, "/"); slash >= 0 {
		file = file[slash+1:]
	}
	for _, filter := range l.vmodule.filter {
		if filter.match(file) {
			l.vmap[pc] = filter.level
			return filter.level
		}
	}
	l.vmap[pc] = 0
	return 0
}

type Verbose bool

func V(level Level) Verbose {

	if atomic.LoadInt32(&logging.filterLength) > 0 {
		logging.mu.Lock()
		defer logging.mu.Unlock()
		if runtime.Callers(2, logging.pcs[:]) == 0 {
			return Verbose(false)
		}
		v, ok := logging.vmap[logging.pcs[0]]
		if !ok {
			v = logging.setV(logging.pcs[0])
		}
		return Verbose(v >= level)
	}
	return Verbose(false)
}

func (v Verbose) Info(args ...interface{}) {
	if v {
		logging.print(infoLog, args...)
	}
}

func (v Verbose) Infoln(args ...interface{}) {
	if v {
		logging.println(infoLog, args...)
	}
}
func (v Verbose) Infof(format string, args ...interface{}) {
	if v {
		logging.printf(infoLog, format, args...)
	}
}

func Info(args ...interface{}) {
	logging.print(infoLog, args...)
}

func InfoDepth(depth int, args ...interface{}) {
	logging.printDepth(infoLog, depth, args...)
}

func Infoln(args ...interface{}) {
	logging.println(infoLog, args...)
}

func Infof(format string, args ...interface{}) {
	logging.printf(infoLog, format, args...)
}

func Debug(args ...interface{}) {
	logging.print(debugLog, args...)
}

func DebugDepth(depth int, args ...interface{}) {
	logging.printDepth(debugLog, depth, args...)
}

func Debugln(args ...interface{}) {
	logging.println(debugLog, args...)
}

func Debugf(format string, args ...interface{}) {
	logging.printf(debugLog, format, args...)
}

func Warn(args ...interface{}) {
	logging.print(warningLog, args...)
}

func WarnDepth(depth int, args ...interface{}) {
	logging.printDepth(warningLog, depth, args...)
}

func Warnln(args ...interface{}) {
	logging.println(warningLog, args...)
}

func Warnf(format string, args ...interface{}) {
	logging.printf(warningLog, format, args...)
}

func Error(args ...interface{}) {
	logging.print(errorLog, args...)
}

func ErrorDepth(depth int, args ...interface{}) {
	logging.printDepth(errorLog, depth, args...)
}

func Errorln(args ...interface{}) {
	logging.println(errorLog, args...)
}

func Errorf(format string, args ...interface{}) {
	logging.printf(errorLog, format, args...)
}

func Fatal(args ...interface{}) {
	logging.print(fatalLog, args...)
}

func FatalDepth(depth int, args ...interface{}) {
	logging.printDepth(fatalLog, depth, args...)
}

func Fatalln(args ...interface{}) {
	logging.println(fatalLog, args...)
}

func Fatalf(format string, args ...interface{}) {
	logging.printf(fatalLog, format, args...)
}

var fatalNoStacks uint32

func Exit(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.print(fatalLog, args...)
}

func ExitDepth(depth int, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printDepth(fatalLog, depth, args...)
}

func Exitln(args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.println(fatalLog, args...)
}

func Exitf(format string, args ...interface{}) {
	atomic.StoreUint32(&fatalNoStacks, 1)
	logging.printf(fatalLog, format, args...)
}
