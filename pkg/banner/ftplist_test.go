package banner

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFTPListAnonymous(t *testing.T) {
	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlLn.Close()
	port := ctrlLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := ctrlLn.Accept()
			if err != nil {
				return
			}
			go handleFakeFTP(t, c)
		}
	}()

	files, err := FTPList("127.0.0.1", port, 5*time.Second)
	if err != nil {
		t.Fatalf("FTPList: %v", err)
	}
	got := strings.Join(files, ",")
	if got != ".,..,documentos,foto1.jpg,leeme.txt" {
		t.Fatalf("files = %q", got)
	}
}

func TestFTPListLoginDenied(t *testing.T) {
	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ctrlLn.Close()
	port := ctrlLn.Addr().(*net.TCPAddr).Port

	go func() {
		c, err := ctrlLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := newLineReader(c)
		fmt.Fprint(c, "220 Deny Server\r\n")
		fmt.Fprint(c, "530 Login incorrect\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "QUIT") {
				fmt.Fprint(c, "221 bye\r\n")
				return
			}
		}
	}()

	if _, err := FTPList("127.0.0.1", port, 5*time.Second); err == nil {
		t.Fatal("esperaba error de login")
	}
}

type lineReader struct{ r io.Reader }

func newLineReader(r io.Reader) *lineReader { return &lineReader{r} }

func (l *lineReader) ReadString(delim byte) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := l.r.Read(buf)
		if n > 0 {
			sb.WriteByte(buf[0])
			if buf[0] == delim {
				return sb.String(), nil
			}
		}
		if err != nil {
			return sb.String(), err
		}
	}
}

func handleFakeFTP(t *testing.T, c net.Conn) {
	defer c.Close()
	fmt.Fprint(c, "220 Fake FTP Server ready\r\n")
	br := newLineReader(c)
	var dataPort int
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "USER"):
			fmt.Fprint(c, "331 Password required\r\n")
		case strings.HasPrefix(line, "PASS"):
			fmt.Fprint(c, "230 Logged in\r\n")
		case strings.HasPrefix(line, "TYPE"):
			fmt.Fprint(c, "200 Type set\r\n")
		case strings.HasPrefix(line, "PASV"):
			dl, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return
			}
			dataPort = dl.Addr().(*net.TCPAddr).Port
			fmt.Fprintf(c, "227 Entering Passive Mode (127,0,0,1,%d,%d)\r\n", dataPort/256, dataPort%256)
			go func() {
				d, err := dl.Accept()
				if err != nil {
					return
				}
				defer d.Close()
				fmt.Fprint(d, "total 4\r\n")
				fmt.Fprint(d, "drwxr-xr-x 1 ftp ftp 0 Jan 1 00:00 .\r\n")
				fmt.Fprint(d, "drwxr-xr-x 1 ftp ftp 0 Jan 1 00:00 ..\r\n")
				fmt.Fprint(d, "drwxr-xr-x 1 ftp ftp 0 Jan 1 00:00 documentos\r\n")
				fmt.Fprint(d, "-rw-r--r-- 1 ftp ftp 123 Jan 1 00:00 foto1.jpg\r\n")
				fmt.Fprint(d, "-rw-r--r-- 1 ftp ftp 45 Jan 1 00:00 leeme.txt\r\n")
			}()
		case strings.HasPrefix(line, "LIST"):
			fmt.Fprint(c, "150 Here comes the directory listing\r\n")
		case strings.HasPrefix(line, "QUIT"):
			fmt.Fprint(c, "221 Goodbye\r\n")
			return
		}
	}
}
