// NOTE: The contents of this file will only be executed if
// you uncomment its entry in "assets/js/app.js".


export default class DemoSocket {
  constructor() {
    this.ping_count = -1
    this.link_el = document.getElementById("demo_socket")
    this.connect_button = document.getElementById("demo_socket_connect")
    this.exec_button = document.getElementById("demo_socket_execute")
    this.stmt_field = document.getElementById("demo_socket_statement")
    this.result_holder = document.getElementById("demo_socket_result")

    this.connect_button.addEventListener("click", this.connect)
    this.exec_button.addEventListener("click", this.exec)
  }

  connect = (_e) => {
    if (this.socket) return

    let href = new URL(this.link_el.href)
    if ("http:" == href.protocol) {
      href.protocol = "ws:"
    } else {
      href.protocol = "wss:"
    }
    href.pathname += "/websocket"

    this.socket = new WebSocket(href)
    this.socket.addEventListener("open", this.did_open)
    this.socket.addEventListener("close", this.did_close)
    this.socket.addEventListener("error", this.did_error)
    this.socket.addEventListener("message", this.got_message)

    this.connect_button.disabled = true
  }

  exec = (_e) => {
    if (!this.socket) return

    this.result_holder.innerText = ""
    this.socket.send(this.stmt_field.value)
  }

  did_open = (_e) => {
    this.exec_button.disabled = false
    this.result_holder.innerText = "did connect"
  }

  did_close = (_e) => {
    this.socket = null
    this.exec_button.disabled = true
    this.connect_button.disabled = false
  }

  did_error = (error_event) => {
    console.log("socket error", error_event)
    this.socket = null
    this.exec_button.disabled = true
    this.connect_button.disabled = true
  }

  got_message = (mesg) => {
    let el = document.createElement("li")
    el.innerText = mesg.data
    this.result_holder.append(el)
  }
}

if (document.getElementById("demo_socket")) {
  window.demo_socket = new DemoSocket()
}
