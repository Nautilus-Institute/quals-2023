let ws = null;
let ws_callback = null;
let ws_promise = null;

window.ticket = localStorage.getItem('ticket');

let ticket_input = document.querySelector('#ticket');
let ticket_error = document.querySelector('#ticket-error');
if (window.ticket) {
  ticket_input.value = window.ticket;
}
function get_valid_ticket() {
  let ticket = ticket_input.value;
  if (!ticket.match(/^ticket\{.*\}$/)) {
    return null;
  }
  return ticket;
}
ticket_input.addEventListener('change', check_ticket);

async function check_ticket(set=false) {
  let old_ticket = window.ticket;
  let ticket = get_valid_ticket();
  if (!ticket) {
    ticket_error.innerText = 'Invalid ticket\ntry to paste again';
  } else {
    ticket_error.innerText = '';
  }
  if (!set || !ticket) {
    return;
  }
  window.ticket = ticket;

  try {
    await get_ws_connection();
  } catch (e) {
    try {
      let res = await fetch('/ws/ticket', {headers:{ticket:window.ticket}});
      if (res.status == 429) {
        ticket_error.innerText = 'Too many requests\ntry again later';
        return;
      }
      if (res.status != 400 && res.status != 500) {
        window.ticket = old_ticket;
        ticket_error.innerText = 'Ticket rejected\ntry to paste again';
        return;
      }
    } catch (e) {}
    console.error(e);
    window.ticket = old_ticket;
    ticket_error.innerText = 'error checking ticket...';
    return;
  }

  localStorage.setItem('ticket', window.ticket);
  done_ticket();
  loadDir('.');
}

function get_ws() {
  return ws;
}


async function get_ws_connection() {
  if (ws == null) {
    ws = new WebSocket(`ws://${location.host}/ws/`,[encodeURIComponent(window.ticket)]);

    let ws_p = new Promise((resolve, reject) => {
      ws.onopen = function() {
        resolve(ws);
      };
      ws.onerror = function(e) {
        reject(e);
      }
    }).catch((e) => {
      ws = null;
      ticket_error.innerText = 'connection error\nsubmit to reconnect';
      get_ticket();
      throw e;
    });
    ws.onmessage = function(e) {
      if (e.data.startsWith('log ')) {
        return;
      }
      if (ws_promise == null) {
        return;
      }
      if (e.data.startsWith('error ')) {
        console.error(e.data);
        ws_callback[1](e.data);
        ws_promise = null;
        return;
      }
      ws_callback[0](e.data);
      ws_promise = null;
    };
    ws.onclose = function() {
      ws = null;
      ws_callback = null
      ws_promise = null;
    };
    return await ws_p;
  }
  return ws;
}

async function send_request(request) {
  let ws = await get_ws_connection();
  let p = new Promise((resolve, reject) => {
    ws_callback = [resolve, reject];
  });
  ws_promise = p;
  ws.send(request);
  return p;
}

async function upload(name, data) {
  let res = await send_request(`upload ${encodeURIComponent(name)} ${data}`);
  setTimeout(()=>{
    loadDir(".");
  }, 500);
  return 'Success';
}


async function listdir(path) {
  let res = await window.send_request(`list ${encodeURIComponent(path)}`);
  res = res.trim().split(" ");
  let found = {};
  let files = [];
  for (let f of res.slice(1)) {
    f = decodeURIComponent(f);
    if (f.includes('.tar') || f.includes('.zip')) {
      continue;
    }
    if (found[f]) {
      continue;
    }
    let type = 'file';
    if (f.endsWith('/')) {
      type = 'directory';
    }
    found[f] = true;
    files.push({
      name: f,
      path: f,
      type: type
    });
  }
  return files;
}

async function gettext(path) {
  let res = await window.send_request(`download ${encodeURIComponent(path)}`);
  res = res.trim().split(" ");
  if (res.length < 3) {
    return 'Error loading file';
  }
  if (res[0] != "file") {
      return 'Error loading file';
  }
  return atob(res[2]);
}

let page_stack = [];
function next_page() {
  let ctx = page_stack.pop();
  page_stack.push(ctx);
  ctx.index++;
  if (!ctx.cb(ctx.data, ctx.index)) {
    ctx.index--;
    ctx.cb(ctx.data, ctx.index)
  }
}
function prev_page() {
  let ctx = page_stack.pop();
  page_stack.push(ctx);
  if (ctx.index == 0)
    return;
  ctx.index--;
  if (!ctx.cb(ctx.data, ctx.index)) {
    ctx.index++;
    ctx.cb(ctx.data, ctx.index)
  }
}
function new_page_ctx(data, cb) {
  page_stack.push({ data, cb, index: 0 });
  cb(data, 0);
}
function pop_page_ctx() {
  if (page_stack.length <= 1) {
    return;
  }
  page_stack.pop();
  let ctx = page_stack.pop();
  if (ctx) {
    page_stack.push(ctx);
    ctx.cb(ctx.data, ctx.index);
  }
}
document.getElementById('up').addEventListener('click', () => {
  prev_page();
});
document.getElementById('down').addEventListener('click', () => {
  next_page();
});

let last_path = null;

function updateBreadcrumbs(path) {
    breadcrumb.innerHTML = '';
    if (path == null) {
      return;
    }

    breadcrumb.append('(- ');

    let o = '';
    path = path.trim();
    if (path[path.length - 1] == '/') {
      path = path.slice(0, -1);
    }
    let path_parts = path.split('/');
    for (let p of path_parts) {
      if (p == '') {
        continue;
      }
      o += p + '/';

      if (path_parts[path_parts.length - 1] != p) {
        if (p == '.') {
          p = 'packages';
        }
        p = p.slice(0, 1);
      } else if (p == '.') {
        p = 'packages';
        last_path = o.slice();
      }

      let dir_name = o.slice();

      let a = document.createElement('a');
      a.innerText = p;
      p = p.slice(0,18);
      a.href='#';
      a.onclick = ()=>{
        loadDir(dir_name);
        return false;
      };
      breadcrumb.appendChild(a);
      breadcrumb.append('/');
    }
}

document.getElementById('updir').addEventListener('click', () => {
  pop_page_ctx();
});

async function loadDir(path) {
    const fileList = document.querySelector('#file-list');
    const breadcrumb = document.querySelector('#breadcrumb');
    let files = await listdir(path);


    if (files.length == 0) {
      document.querySelector('#file-content').style.display = 'none';
      document.querySelector('#file-list').style.display = 'block';

      fileList.innerHTML = '';
      fileList.append('\n\n Your bunker is empty.\n\n Drag and drop an archive');
      return true;
    }

    const page_len = 6;
    new_page_ctx(files, (files, current_page) => {
      const pages = Math.ceil(files.length / page_len);
      files = files.slice(current_page * page_len, (current_page + 1) * page_len);
      if (files.length == 0) {
        return false;
      }

      document.querySelector('#file-content').style.display = 'none';
      document.querySelector('#file-list').style.display = 'block';
      updateBreadcrumbs(path);

      fileList.innerHTML = '';

      let s = document.createElement('span');
      s.style.width = '100%';
      s.style.textAlign = 'right';
      s.style.display = 'inline-block';
      s.innerText = `Page ${current_page+1}/${pages}`;
      fileList.appendChild(s);

      for (let i=0; i< 6; i++) {
        let b = document.getElementById(`b${i+1}`);
        b.onclick = ()=>{};
      }

      files.forEach((file,ind) => {
          const li = document.createElement('li');
          li.className = file.type;

          li.style.width = '100%';

          if (ind % 2 == 0) {
            li.append('(-');
            li.style.textAlign = 'left';
          }

          const a = document.createElement('a');
          a.textContent = file.name.slice(0, 26);
          a.href = '#';

          function load_path() {
              if (file.type === 'directory') {
                  loadDir(`${path}/${file.path}`);
              } else {
                loadFile(`${path}/${file.path}`);
              }
              return false;
          }

          a.onclick = load_path;
          let b = document.getElementById(`b${ind+1}`);
            b.onclick = load_path;
          li.appendChild(a);
          if (ind % 2 == 1) {
            li.append('-)');
            li.style.textAlign = 'right';
          }
          li.append('\n');
          fileList.appendChild(li);
      });
      return true;
    });
}

async function loadFile(path) {
    const fileContent = document.querySelector('#file-content');

    const text = await window.gettext(path);

    let lines = text.split('\n');
    const line_len = 29;
    let all_lines = [];
    for (let l of lines) {
      for (let i=0; i<l.length; i+=line_len) {
        all_lines.push(l.slice(i, i+line_len));
      }
    }


    const page_len = 6;
    new_page_ctx(all_lines, (lines, current_page) => {
      for (let i=0; i< 6; i++) {
        let b = document.getElementById(`b${i}`);
        if (!b) continue;
        b.onclick = ()=>{};
      }

      document.querySelector('#file-content').style.display = 'block';
      document.querySelector('#file-list').style.display = 'none';
      updateBreadcrumbs(path);

      const pages = Math.ceil(lines.length / page_len);
      lines = lines.slice(current_page * page_len, (current_page + 1) * page_len);
      if (lines.length == 0) {
        return false;
      }
      fileContent.innerHTML = '';

      let s = document.createElement('span');
      s.style.width = '100%';
      s.style.textAlign = 'right';
      s.style.display = 'block';
      s.innerText = `Page ${current_page+1}/${pages}\n`;
      fileContent.appendChild(s);

      fileContent.append(lines.join('\n'));
      return true;
    });
}
function get_ticket() {
  document.querySelector('#file-content').style.display = 'none';
  document.querySelector('#file-list').style.display = 'none';
  document.querySelector('#ticket-cfg').style.display = 'block';
  updateBreadcrumbs(null);
  document.querySelector('#bottom-row .left').innerText = '(- Submit-Ticket';
  document.querySelector('#bottom-row .right').innerText = '';

  document.querySelector('#package').onclick = ()=>check_ticket(true);
}
function done_ticket(invalid=false) {
  document.querySelector('#package').onclick = package_artifacts;
  document.querySelector('#ticket-cfg').style.display = 'none';
  document.querySelector('#clean').onclick = clean_all;
  document.querySelector('#bottom-row .left').innerText = '(- Prep-Artifacts   ~';
  document.querySelector('#bottom-row .right').innerText = 'Shred-All-)';
}
if (ticket !== null) {
  ticket_input.value = ticket;
}
let is_on = false;
async function turn_on() {
  is_on = true;
  document.querySelector('.screen-background').style.opacity = '1';
  setTimeout(()=>{
    document.querySelector('.inner-window').style.opacity = '1';
  }, 300);
  if (ticket && ticket.trim().length != 0  && check_ticket()) {
    done_ticket();
    loadDir('.');
  } else {
    get_ticket();
  }
}
async function turn_off() {
  is_on = false;
  document.querySelector('.screen-background').style.opacity = '1';
  document.querySelector('.inner-window').style.opacity = '0';
  setTimeout(()=>{
    document.querySelector('.screen-background').style.opacity = '0';
  }, 300);
}
turn_off();
let glow_interval = null;
document.getElementById('power').onclick = ()=>{
  clearInterval(glow_interval);
  document.getElementById('power').style = 'none';
  if (!is_on) {
    turn_on();
  } else {
    turn_off();
  }
}
setTimeout(()=>{
  document.querySelector('.screen-background').classList.add('screen-fade');
  document.querySelector('.inner-window').classList.add('screen-fade');
}, 500);

glow_interval = setTimeout(()=>{
  let p = document.getElementById('power');
  p.style.transition = 'box-shadow 1s';
  p.style.boxShadow = '0px 0px 10px 5px #00ff00';
  let on = true;
  glow_interval = setInterval(()=>{
    on = !on;
    if (on) {
      p.style.boxShadow = '0px 0px 10px 5px #00ff00';
    } else {
      p.style.boxShadow = 'none';
    }
  }, 1200);

},30000);

document.getElementById('cfg').onclick = async ()=>{
  if (!is_on)
    return;
  get_ticket();
}

let p_c = 0;
async function package_artifacts() {
  if (!is_on)
    return;
  if (p_c + 10000 > +Date.now()) {
    return;
  }
  p_c = +Date.now();
  await window.send_request(`job package app`);
  setTimeout(()=>{
    loadDir('.');
  }, 500);
}

async function clean_all() {
  if (!is_on)
    return;
  let res = window.confirm("Are you sure you want to delete all archives?");
  if (!res) {
    return;
  }
  await window.send_request(`clean-all`);
  setTimeout(()=>{
    loadDir('.');
  }, 500);
}
// Get the body element
var body = document.body;

// Create a function to handle the drop event
function handleDrop(e) {
  // Prevent the default behavior of opening the file
  e.preventDefault();

  // Get the first file from the data transfer object
  var file = e.dataTransfer.files[0];

  // Create a file reader object
  var reader = new FileReader();

  // Create a function to handle the load event
  reader.onload = function(e) {
    // Get the base64 encoded data URL from the result
    var dataURL = e.target.result;
    let name = file.name;

    // Do something with the data URL, such as displaying it in an image element
    var parts = dataURL.split(",");
    var base64 = parts[1];
    window.upload(file.name, base64);
  };

  // Read the file as a data URL
  reader.readAsDataURL(file);
}

// Add an event listener for the dragover event to prevent the default behavior
body.addEventListener("dragover", function(e) {
  e.preventDefault();
});

// Add an event listener for the drop event to handle the file drop
body.addEventListener("drop", handleDrop);
