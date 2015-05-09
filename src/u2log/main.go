package main

import (
        "bufio"
        "encoding/binary"
        "fmt"
        "io"
        "io/ioutil"
        "os"
        "path/filepath"
//        "time"
  "encoding/json"
  "encoding/gob"
  "bytes"
  "log"
  "flag"
)

var WALDO_FILENAME string
var SPOOL_DIR string
var FILE_PATTERN string
var LOG_FILE string
var OUTPUT_FILE string

var operationMode int = -1

func NewUnified2FormatParser(r io.Reader) *Unified2FormatParser {
        return &Unified2FormatParser{
                Reader: bufio.NewReader(r),
        }
}

func (parser *Unified2FormatParser) ReadPacket() (*Unified2_Packet, error) {
        serialized_packet := Serial_Unified2_Header{}
        packet := Unified2_Packet{}

        if err := binary.Read(parser, binary.BigEndian, &serialized_packet); err != nil {
                packet.Type = serialized_packet.Type
                packet.Length = serialized_packet.Length
                return &packet, err
        }
        packet.Type = serialized_packet.Type
        packet.Length = serialized_packet.Length
        
        //fmt.Println("packet.Type:", packet.Type)
        //fmt.Println("packet.Length:", packet.Length)
        /*
        if err := binary.Read(parser, binary.BigEndian, &packet.Length); err != nil {
                return &packet, err
        }
        fmt.Println("packet.Length:", packet.Length)
        */
        packet.Data = make([]byte, packet.Length)

        if _, err := io.ReadFull(parser, packet.Data); err != nil {
                return &packet, err
        }

        return &packet, nil
}

func ReadToBuf() {
}

func producer(files []string, waldo Waldo ,w io.Writer, waldoFile string, finalOut io.Writer) error {
  //buffer:=make([]byte, 0, 4*1024)
  startProcess := false
  jumpedToWaldo := false
        for _, file := range files {
                //fmt.Println("reading:", file)
          if file == waldo.Filename {
            startProcess=true
          }
          if !startProcess {
            continue
          }
          f, err := os.Open(file)
          if err != nil {
            log.Println("[ERR] open file for reading:", file)
            return err
          }
          if (!jumpedToWaldo) {
            jumpedToWaldo = true
            log.Println("[INFO] try seeking ",waldo.Location, " on file ", waldo.Filename)
            currentPos,err := f.Seek(waldo.Location, 0)
            if err != nil || currentPos != waldo.Location {
              f.Close()
              log.Println("[ERR] unable to seek to ", waldo.Location, " of file ", file, " seek reach:", currentPos)
              log.Println("[ERR] skip to next file")
              continue
            }
          }
          /*
          copied,err := io.Copy(w,f)
          if err != nil {
              log.Println("[ERR] copydata to parse error:",err," ,copied:",copied)
          }
          f.Close()
          */
          currentPos,err := f.Seek(0, 1)
          consumer(f, finalOut, waldoFile, currentPos, file)
          f.Close()
        }
        return nil
}

func consumer(r io.Reader, finalOut io.Writer, waldoFile string, lastKnownPosition int64, currentFilename string) error {
	//r io.Reader
        parser := NewUnified2FormatParser(r)
        var lastKnownEvent = new (SnortEventIpv4AppId)
        
        packetCounter := 0

        for {
                packet, err := parser.ReadPacket()
                lastKnownPosition = lastKnownPosition + int64(packet.Length) + 8
                if err != nil && err != io.EOF {
                        fmt.Println("[ERR parsing]", err)
                        return err
                }
                fmt.Printf("Success! (id:%X, len:%d)\n", packet.Type,len(packet.Data))
                if err == io.EOF {
                	break
                }
                
                //dumpHex(packet.Data, 0, 16)
                switch packet.Type {
                  case UNIFIED2_IDS_EVENT_APPID:
                    if lastKnownEvent.Event_id != 0 {
                      // submit to process & mark waldo file
                      DumpJson(lastKnownEvent, finalOut)
                      // reset lastKnownEvent & lastKnowPos
                      lastKnownPosition = lastKnownPosition - int64(packet.Length) - 8
                      lastKnownEvent = new (SnortEventIpv4AppId)
                      fmt.Println("Loc:", lastKnownPosition)
                      
                      waldo := Waldo{currentFilename,lastKnownPosition}
                      WriteWaldo(waldoFile, waldo)
                      
                      packetCounter = packetCounter + 1
                      if packetCounter == 1 {
                      	return nil
                      }
                    }
                    event:= DecodeU2EventApp(packet.Data)
                    //DumpJson(event)
                    //fmt.Println("")
                    lastKnownEvent.Unified2IDSEventAppId = *event
                  case UNIFIED2_EXTRA_DATA:
                    extra:=DecodeU2ExtraData(packet.Data)
                    //DumpJson(extra)
                    //dumpHex(packet.Data,0,len(packet.Data))
                    if extra.Event_id != lastKnownEvent.Event_id {
                      fmt.Println("[WARN]: orphan extra event_id=", extra.Event_id,",expected:", lastKnownEvent.Event_id)
                      continue
                    }
                    if lastKnownEvent.ExtraData == nil {
                      lastKnownEvent.ExtraData = make([]Unified2ExtraData,1)
                      lastKnownEvent.ExtraData[0] = *extra
                    } else {
                      lastKnownEvent.ExtraData = append(lastKnownEvent.ExtraData, *extra)
                    }
                  case UNIFIED2_PACKET:
                    raw_packet:= DecodeU2Packet(packet.Data)
                    //DumpJson(raw_packet)
                    //fmt.Println("Found packet:", raw_packet.Event_id)
                    if raw_packet.Event_id != lastKnownEvent.Event_id {
                      fmt.Println("[WARN]: orphan packet event_id=", raw_packet.Event_id,",expected:", lastKnownEvent.Event_id)
                      continue
                    }
                    if lastKnownEvent.Packets == nil {
                      lastKnownEvent.Packets = make([]RawPacket,1)
                      lastKnownEvent.Packets[0] = *raw_packet
                    } else {
                      lastKnownEvent.Packets = append(lastKnownEvent.Packets, *raw_packet)
                    }

                  default:
                    fmt.Println("[WARN]: packet unknown type=", packet.Type)
                }
        }
        if lastKnownEvent.Event_id != 0 {
          // submit to process
          DumpJson(lastKnownEvent, finalOut)
          fmt.Println("Loc:", lastKnownPosition)
        }
        return nil
}

func WriteWaldo(filename string, w Waldo) {
        var buf bytes.Buffer
        enc := gob.NewEncoder(&buf) // Will write to network.
        err := enc.Encode(w)
        if err != nil {
                log.Println("[ERR] Encode waldo error:", err)
        }
        err = ioutil.WriteFile(filename, buf.Bytes(), 0644)
        if err != nil {
                log.Println("[ERR] Write waldo file error:", err)
        }
}

func ReadWaldo(filename string) Waldo {
        w:=Waldo{}
        content, err := ioutil.ReadFile(filename)
        if err != nil {
                log.Println("[ERR] Read waldo file error:", err)
        } else {
          buf := bytes.NewBuffer(content)
          dec := gob.NewDecoder(buf)
          err = dec.Decode(&w)
          if err != nil && err != io.EOF {
                  log.Println("[ERR] Decode waldo error:", err)
          }
        }
        return w
}

func DumpJson(v interface{}, w io.Writer) {
  if v != nil {
    b,e := json.Marshal(v)
    if (e !=nil) {
      log.Println("[ERR] DumpJson marshal:",e)
    }
    //os.Stdout.Write(b)
    //log.Println(b)
    _,err:=w.Write(b)
    w.Write([]byte{10})
    if err!=nil {
      log.Println("[ERR] DumpJson write:", e)
    }
  }
}

func DumpHex(buf []byte, from int, to int) {
  for i:=from;i<to;i++ {
    fmt.Printf("%02X ",buf[i])
  }
  fmt.Printf("\n")
}

func DecodeU2EventApp (buf []byte) *Unified2IDSEventAppId {
  r := bytes.NewReader(buf)
  e := new(Unified2IDSEventAppId)
  err := binary.Read(r,binary.BigEndian, e)
  if (err == io.EOF) {
    // check(err)
    e = nil
  }
  return e
}

func DecodeU2ExtraData (buf []byte) *Unified2ExtraData {
  r := bytes.NewReader(buf)
  e   := new(Unified2ExtraData)
  err := binary.Read(r,binary.BigEndian, &e.Unified2ExtraDataHdr)
  if (err != nil) {
    // check(err)
    return nil
  }
  err = binary.Read(r,binary.BigEndian, &e.SerialUnified2ExtraData)
  if (err != nil) {
    // check(err)
    return nil
  }
  
  if e.Blob_length-8 <=0 {
    return e
  }
  e.Data = make([]byte, e.Blob_length-8)

  if n,err := io.ReadFull(r, e.Data) ; err != nil && err != io.EOF {
    fmt.Println("[ERR] read extra data:",err, "expected len:",e.Blob_length-8, ",got:",n)
    return e
  }
  
  return e
}

func DecodeU2Packet(buf []byte) *RawPacket {
  r := bytes.NewReader(buf)
  p   := new(RawPacket)
  err := binary.Read(r,binary.BigEndian, &p.Serial_Unified2Packet)
  if (err != nil) {
    // check(err)
    return nil
  }
  err = binary.Read(r,binary.BigEndian, &p.EthHeader)
  if (err != nil) {
    // check(err)
    return nil
  }
  err = binary.Read(r,binary.BigEndian, &p.Ipv4Header)
  if (err != nil) {
    // check(err)
    return nil
  }
  packet_data_size := p.Packet_length - ETH_HEADER_SIZE - IP4_HEADER_SIZE_BASIC 
  p.Data = make([]byte, packet_data_size)
  
  if n,err := io.ReadFull(r, p.Data) ; err != nil && err != io.EOF {
    fmt.Println("[ERR] read packet data:",err, "expected len:",packet_data_size, ",got:",n)
    return p
  }
  
  return p
}

func stringInSlice(a string, list []string) bool {
    for _, b := range list {
        if b == a {
            return true
        }
    }
    return false
}

func checkWaldo(filename string, files []string) error {
    if _, err := os.Stat(filename); os.IsNotExist(err) {
          fmt.Println("No waldo file:",filename,", will process from beginning")
          return os.ErrNotExist 
    } else {
          fmt.Println("Found waldo file, try loading...")
          w:=ReadWaldo(filename)
          if w.Filename=="" {
            fmt.Println("Loading waldo file error")
            return os.ErrInvalid
          } else {
            if !stringInSlice(w.Filename, files) {
              fmt.Println("Incorrect waldo data: Waldo point to file not in glob pattern")
              fmt.Println(w.Filename, " not in ", files)
              return os.ErrInvalid
            }
            fi,err := os.Stat(w.Filename)
            if err != nil {
              fmt.Println(err)
              return os.ErrInvalid
            }
            if w.Location >= fi.Size() {
              fmt.Println("Incorrect waldo data: location >= file size")
              fmt.Println("marked location:", w.Location, ",file size:", fi.Size())
              return os.ErrInvalid
            }
          }
    }
        return nil
}

func initConfig() {
  flag.StringVar(&WALDO_FILENAME,"w","-", "marking file, used to store last read location")
  flag.StringVar(&FILE_PATTERN,"f","-", "input file pattern (glob)")
  flag.StringVar(&LOG_FILE,"l","-", "Output log to a separate file")
  flag.StringVar(&OUTPUT_FILE,"o","-","Output to file or - to stdout")

  flag.Parse()
  if len(os.Args) < 2 {
    flag.PrintDefaults()
    os.Exit(1)
  }

    if FILE_PATTERN=="-" || WALDO_FILENAME=="-" {
      //flag.PrintDefaults()
      log.Fatal("Must provide correct waldo file & file name pattern")
    } else {
      fmt.Println("Spooling mode, checking params")
      files, err := filepath.Glob(FILE_PATTERN)
      if err != nil {
                fmt.Println("Glob pattern error:",err)
                os.Exit(-1)
      }
      err = checkWaldo(WALDO_FILENAME, files)
      if err != nil && err != os.ErrNotExist {
      	os.Exit(-1)
      }
    }
  
  if (LOG_FILE != "-") {
    log.Println("Log will be output to ", LOG_FILE)
    lf, err := os.OpenFile(LOG_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatal("Failed to open log file", err)
    }
    log.SetOutput(lf)
  } else {
    fmt.Println("Log will be output to console")
  }
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func main() {
        var finalOut io.Writer
        var f os.File
        initConfig()

        if OUTPUT_FILE != "-" {
          f,err := os.OpenFile(OUTPUT_FILE, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
          check(err)
          finalOut = bufio.NewWriter(f) 
        } else {
          finalOut = os.Stdout
        }
        defer f.Close()

        files, err := filepath.Glob(FILE_PATTERN)
        if err != nil {
                fmt.Println(err)
                os.Exit(-1)
        }
        fmt.Println("FILE_PATTERN=", FILE_PATTERN)
        fmt.Println(files)
        
        waldo := ReadWaldo(WALDO_FILENAME)
        if waldo.Filename == "" {
        	waldo.Filename = files[0]
        }
        
        //pipeReader, pipeWriter := io.Pipe()

        //go consumer(pipeReader, finalOut, WALDO)

        if err = producer(files, waldo, nil, WALDO_FILENAME, finalOut); err != nil {
                fmt.Println(err)
        }

        //pipeWriter.Close()
        //pipeReader.Close()
        //time.Sleep(1 * time.Second)
}
