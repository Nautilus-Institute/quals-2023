package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"golang.org/x/net/websocket"
	"gopkg.in/yaml.v3"

)

func wlog(ws *websocket.Conn, format string, v ...interface{}) {
	msg := fmt.Sprintf("log "+format, v...)
	websocket.Message.Send(ws, msg)
}

func wsend(ws *websocket.Conn, format string, v ...interface{}) {
	msg := fmt.Sprintf(format, v...)
	websocket.Message.Send(ws, msg)
}

func file_exists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func get_file_name(path string) string {
	path = filepath.Clean(path)
	name := filepath.Base(path)
	return name
}

type Config struct {
	filter_secrets []string
	filter_ignore  []string
	project_root   string
	job_file       string
}

func LoadConfig(path string) *Config {
	c := &Config{}
	yaml_file, err := ioutil.ReadFile(path)
	if err != nil {
		panic("No config file fond")
		return nil
	}
	var result interface{}
	err = yaml.Unmarshal(yaml_file, &result)
	if err != nil {
		panic(fmt.Sprintf("Error parsing config file: %s", err))
		return nil
	}
	j := result.(map[string]interface{})
	c.project_root = j["root"].(string)
	c.job_file = j["job"].(string)
	filter := j["filter"].(map[string]interface{})

	for _, v := range filter["secrets"].([]interface{}) {
		c.filter_secrets = append(c.filter_secrets, v.(string))
	}
	for _, v := range filter["ignore"].([]interface{}) {
		c.filter_ignore = append(c.filter_ignore, v.(string))
	}
	return c
}

var CONFIG *Config

type UploadReader struct {
	zr    *zip.ReadCloser
	tr    *tar.Reader
	index int
}

func NewUploadReader(path string) *UploadReader {
	if !file_exists(path) {
		return nil
	}
	ext := filepath.Ext(path)
	if ext != ".zip" && ext != ".tar" {
		return nil
	}

	o := &UploadReader{
		zr:    nil,
		tr:    nil,
		index: 0,
	}
	if ext == ".zip" {
		zr, err := zip.OpenReader(path)
		o.zr = zr
		if err != nil {
			return nil
		}
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil
		}
		o.tr = tar.NewReader(file)
	}
	return o
}

func (u *UploadReader) Next() (string, io.Reader, error) {
	if u.zr != nil {
		if u.index >= len(u.zr.File) {
			return "", nil, io.EOF
		}
		f := u.zr.File[u.index]
		u.index += 1
		name := f.Name
		rc, _ := f.Open()
		return name, rc, nil
	}
	if u.tr != nil {
		f, err := u.tr.Next()
		if err != nil {
			return "", nil, err
		}
		name := f.Name
		return name, u.tr, nil
	}
	return "", nil, errors.New("Bad UploadReader")
}

func (u *UploadReader) Close() {
	if u.zr != nil {
		u.zr.Close()
	}
}

func is_file_ignored(path string) bool {
	path = strings.ToLower(path)
	for _, n := range CONFIG.filter_ignore {
		if strings.Contains(path, n) {
			return false
		}
	}
	return true
}

func is_project_file(path string) (string, error) {
	path = filepath.Clean(path)
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	path = strings.ToLower(path)
	for _, bad := range []string{"/proc", "/data", "/dev", "/sys", "/run", "/var"} {
		if strings.Contains(path, bad) {
			return "", errors.New("Bad path")
		}
	}

	if !strings.HasPrefix(path, CONFIG.project_root) {
		return "", errors.New("Bad path")
	}
	return path, nil
}

func run_job(ws *websocket.Conn, job string, args []string) {
	if job != "package" {
		wsend(ws, "error Unknown job `%s`", job)
		return
	}

	job_path := filepath.Join(CONFIG.project_root, CONFIG.job_file)
	job_path, err := is_project_file(job_path)
	if err != nil {
		wsend(ws, "error File `%s` is not a valid archive job", job)
		return
	}

	tmpl, err := template.ParseFiles(job_path)
	if err != nil {
		wsend(ws, "error File `%s` is not a valid artifact job", job)
		return
	}

	name, err := url.PathUnescape(args[0])
	if err != nil {
		wsend(ws, "error Name `%s` is not a valid", args[0])
		return
	}

	data := struct {
		Name      string
		Commit    string
		Timestamp string
	}{
		Name:   name,
		Commit: "main",
		Timestamp: strconv.FormatInt(time.Now().Unix(), 10),
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		wsend(ws, "error File `%s` is not a valid job config, failed to template", job)
		return
	}

	var result interface{}
	err = yaml.Unmarshal(buf.Bytes(), &result)
	if err != nil {
		wsend(ws, "error File `%s` is not a valid job yaml", job)
		return
	}

	files_to_archive := []string{}

	json := result.(map[string]interface{})
	jobs := json["job"].(map[string]interface{})
	steps := jobs["steps"].([]interface{})
	for _, step := range steps {
		step_map := step.(map[string]interface{})
		artifacts := step_map["artifacts"].([]interface{})
		for _, artifact := range artifacts {
			artifact_name := artifact.(string)
			artifact_path := filepath.Join(CONFIG.project_root, artifact_name)
			artifact_path, err = is_project_file(artifact_path)
			if err != nil {
				continue
			}
			files_to_archive = append(files_to_archive, artifact_path)
		}
		archive_name := step_map["name"].(string)

		archive_files(ws, archive_name, files_to_archive)
	}

	wsend(ws, "job complete")
}

func clean_all(ws *websocket.Conn) {
	files, err := ioutil.ReadDir("/data")
	if err != nil {
		wsend(ws, "error Failed to list files")
		return
	}

	for _, f := range files {
		if !f.IsDir() {
			os.Remove(filepath.Join("/data", f.Name()))
		}
	}
	time.Sleep(1 * time.Second)
	wsend(ws, "clean-all complete")
}

func list_files(ws *websocket.Conn, path string) {
	path, err := url.PathUnescape(path)
	if err != nil {
		wsend(ws, "error Invalid name")
	}
	real_path := "/data/" + path

	info, _ := os.Stat(real_path)
	if info == nil || !info.IsDir() {
		path = filepath.Clean(path)
		_, chil := find_archive_file(ws, path)
		if chil == nil {
			wsend(ws, "error Directory `%s` not found", path)
			return
		}
		out := ""
		for _, c := range chil {
			out += url.QueryEscape(c) + " "
		}
		wsend(ws, "files %s", out)
		return
	}

	files, err := ioutil.ReadDir(real_path)
	if err != nil {
		wsend(ws, "error Unable to list files")
		return
	}
	out := ""
	for _, f := range files {
		name := f.Name()
		out += url.QueryEscape(name) + "/ "
	}
	wsend(ws, "files %s", out)
}

func archive_files(ws *websocket.Conn, name string, files []string) {
	name, err := url.PathUnescape(name)
	if err != nil {
		wsend(ws, "error Invalid backup name")
	}
	name = get_file_name(name)
	t_path := filepath.Join("/data", name+".tar")
	if file_exists(name) {

		err = os.Remove(t_path)
		if err != nil {
			wsend(ws, "error Unable to delete old backup")
			return
		}
	}
	t_file, err := os.OpenFile(t_path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		wsend(ws, "error Unable to create backup archive")
		return
	}

	defer t_file.Close()
	tw := tar.NewWriter(t_file)

	for _, fn := range files {
		fp, err := url.PathUnescape(fn)
		if err != nil {
			wsend(ws, "error Invalid file name")
			break
		}
		fp = filepath.Clean(fp)
		fp, err = filepath.Abs(fp)
		if err != nil {
			wsend(ws, "error Invalid file name")
			break
		}

		fp, err = is_project_file(fp)
		if err != nil {
			wsend(ws, "error File `%s` cannot be an artifact, only files in `%s` can be artifacts", fp, CONFIG.project_root)
			break
		}

		if err != nil || !file_exists(fp) {
			wsend(ws, "error File `%s` not found", fp)
			break
		}

		info, _ := os.Stat(fp)
		fh, _ := tar.FileInfoHeader(info, "")
		fh.Name = fp
		tw.WriteHeader(fh)

		if fr, err := os.Open(fp); err == nil {
			io.Copy(tw, fr)
			fr.Close()
		}
	}

	tw.Close()

	_, err = compress_files(ws, t_path)
	if err != nil {
		wsend(ws, "error Unable to compress backup archive")
		return
	}
}

func compress_files(ws *websocket.Conn, in_path string) (string, error) {
	in_ext := filepath.Ext(in_path)
	out_path := strings.TrimSuffix(in_path, in_ext)

	dir_name := get_file_name(out_path)

	ur := NewUploadReader(in_path)
	if ur == nil {
		return "", errors.New("Unable to read upload archive")
	}


	out_file, err := os.OpenFile(out_path, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return "", errors.New("Unable to create compressed directory")
	}
	defer out_file.Close()

	zw := zip.NewWriter(out_file)

	for {
		name, fr, err := ur.Next()
		if err == io.EOF {
			break
		}

		name = strings.TrimLeft(name, "/")


		fw, _ := zw.Create(name)

		if !is_file_ignored(name) {
			fw.Write([]byte("***\n"))
			continue
		}

		// Read full file into memory
		file_data, err := ioutil.ReadAll(fr)

		for _, r := range CONFIG.filter_secrets {
			re := regexp.MustCompile(r)
			file_data = re.ReplaceAll(file_data, []byte("***"))
		}

		fw.Write(file_data)
	}

	ur.Close()
	zw.Close()
	return dir_name, nil
}

func find_archive_file(ws *websocket.Conn, path string) (string, []string) {
	path = strings.Trim(path, "/")

	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 1 {
		wsend(ws, "error Path not found")
		return "", nil
	}
	if len(parts) < 2 {
		parts = append(parts, "")
	}
	z_path := get_file_name(parts[0])

	fname := parts[1]

	z_path = filepath.Join("/data", z_path)

	if !file_exists(z_path) {
		wsend(ws, "error Directory `%s` not found", fname)
		return "", nil
	}

	zr, err := zip.OpenReader(z_path)
	if err != nil {
		wsend(ws, "error Unable to open archive directory")
		return "", nil
	}

	children := make([]string, 0)

	for _, f := range zr.File {
		if f.Name == fname {
			rc, _ := f.Open()

			var bldr strings.Builder
			b64e := base64.NewEncoder(base64.StdEncoding, &bldr)
			io.Copy(b64e, rc)
			b64e.Close()

			b64 := bldr.String()

			rc.Close()
			zr.Close()
			return b64, children
		} else if strings.HasPrefix(f.Name, fname) {
			rest := strings.TrimPrefix(f.Name, fname)
			rest = strings.TrimPrefix(rest, "/")

			parts := strings.SplitN(rest, "/", 2)
			top_dir := parts[0]
			if len(parts) > 1 {
				top_dir += "/"
			}
			children = append(children, top_dir)
		}
	}
	zr.Close()
	return "", children
}

func get_file(ws *websocket.Conn, path string) {
	path, err := url.PathUnescape(path)
	if err != nil {
		wsend(ws, "error Invalid path")
		return
	}
	path = filepath.Clean(path)

	b64, _ := find_archive_file(ws, path)
	if b64 == "" {
		wsend(ws, "error File `%s` not found", path)
		return
	}
	wsend(ws, "file %s %s", url.PathEscape(path), b64)
}

func upload(ws *websocket.Conn, name string, b64data string) {
	name, err := url.PathUnescape(name)
	if err != nil {
		wsend(ws, "error Invalid file name")
		return
	}

	name = get_file_name(name)
	ext := filepath.Ext(name)
	if ext != ".zip" && ext != ".tar" {
		wsend(ws, "error Unsupported upload type `%s`", ext)
		return
	}

	if file_exists(name) {
		wsend(ws, "error Backup archive `%s` already exists", name)
		return
	}

	b64data = strings.Trim(b64data, " ")

	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		wsend(ws, "error Failed to decode base64 data")
		os.Exit(0)
	}

	path := filepath.Join("/data", name)

	ioutil.WriteFile(path, data, 0644)

	dir_name, err := compress_files(ws, path)
	if err != nil {
		wsend(ws, "error Failed to create remote directory")
		return
	}
	wsend(ws, "upload-success %s Remote directory `%s` created", url.PathEscape(dir_name), dir_name)
}

func run_command(ws *websocket.Conn, cmd string) {
	defer func() {
		err := recover()
		if err != nil {
			wsend(ws, "error `%s`", err)
		}
	}()

	parts := strings.Split(cmd, " ")
	if parts[0] == "upload" {
		upload(ws, parts[1], parts[2])
	} else if parts[0] == "download" {
		get_file(ws, parts[1])
	} else if parts[0] == "list" {
		list_files(ws, parts[1])
	} else if parts[0] == "clean-all" {
		clean_all(ws)
	} else if parts[0] == "job" {
		run_job(ws, parts[1], parts[2:])
	} else {
		wsend(ws, "error Unknown Cmd `%s`!", parts[0])
		os.Exit(0)
	}
}

func handleConnections(ws *websocket.Conn) {
	var msg string
	for {
		err := websocket.Message.Receive(ws, &msg)
		if err != nil {
			if err == io.EOF {
				break
			}
			break
		}

		run_command(ws, msg)
	}
}

func main() {
	CONFIG = LoadConfig("/opt/project.cfg")

	http.Handle("/ws/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Origin", "http://"+r.Host)
		websocket.Handler(handleConnections).ServeHTTP(w, r)
	}))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/index.html")
	})
	http.HandleFunc("/style.css", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/style.css")
	})
	http.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/app.js")
	})

	// Serve files from static
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("http server started on :5555")
	err := http.ListenAndServe(":5555", nil)
	if err != nil {
		fmt.Println("Failed to bind socket")
	}
}
