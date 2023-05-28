import select
import subprocess
import sys
import time

for i in range(2):
    sacrificial_netcat = subprocess.Popen(['nc', '-l', '28080'])
    print("sacrificial netcat is a go", file=sys.stderr)
    time.sleep(1)
    sacrificial_netcat.kill()
    print("thank you, sacrificial netcat", file=sys.stderr)
    print("what the fuck, docker", file=sys.stderr)

proc = subprocess.Popen(
    ["wine", "./ChatTGE.exe"] + sys.argv[2:], stderr=subprocess.PIPE)

needle = b'starting debugger...'
poll = select.poll()
poll.register(proc.stderr, select.POLLIN)
output_buffer = b''
while proc.poll() is None:
    result = poll.poll(100)
    if not result:
        continue

    output = proc.stderr.read1()
    sys.stdout.buffer.write(output)
    output_buffer += output
    if needle in output_buffer:
        proc.kill()
        break

    if len(output_buffer) >= len(needle):
        output_buffer = output_buffer[-len(needle):]
