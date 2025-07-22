from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
import asyncio
import socket
from ipaddress import ip_address, ip_network
import concurrent.futures
import multiprocessing
import uvicorn
import os 
from fastapi.responses import Response



PORT_TIMEOUT = 2
app = FastAPI()

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
else:
    print("[!] Error DIR: 'static/' directory not found. Static files not mounted.")

#DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 8080, 8443]
max_threads = multiprocessing.cpu_count() * 4
executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)

def DATA_SAVE(result, filename):
    with open(f'Success_Results/{filename}', "a") as save:
        save.write(f'{result}\n')

# prevent crash and shutdown cleanup
@app.on_event("shutdown")
def shutdown_event():
    print("[!] Shutting down ThreadPoolExecutor...")
    executor.shutdown(wait=False)
    
async def THREAD_PORTSCAN(host, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 8080, 8443]):
    
    loop = asyncio.get_running_loop()
    result = {"target": host, "open_ports": [], "closed_ports": []} 
    
    def Scan_Ported(port):
        try:
            conn = socket.create_connection((host, int(port)), timeout=PORT_TIMEOUT)
            conn.close()
            
            return (port, True)
        except:
            return (port, False)

    tasks = [loop.run_in_executor(executor, Scan_Ported, port) for port in ports]

    for future in asyncio.as_completed(tasks):
        port, Port_Success = await future
        if Port_Success:
            DATA_SAVE(f'{host}:{port}', 'Live_Data.txt')
            result["open_ports"].append(port)
        else:
            result["closed_ports"].append(port)

    if result["open_ports"]:
        DATA_SAVE(host, 'Live_IP.txt')

    else:
        DATA_SAVE(host, 'RIP_Data.txt')

    
    return result

def IP_Ranger(start_ip, end_ip):
    try:
        start = int(ip_address(start_ip))
        end = int(ip_address(end_ip))
        if end < start:
            start, end = end, start
        return [str(ip_address(ip)) for ip in range(start, end + 1)]
    except ValueError:
        return []

@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("static/index.html", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return HTMLResponse(f"<h1>Error loading HTML: {e}</h1>", status_code=500)

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()

    scan_task = None
    scan_cancel_event = asyncio.Event()

    async def fire_scanner(data):
        mode = data.get("mode")
        ports_ = [int(p.strip()) for p in data.get("ports", "").split(",") if p.strip().isdigit()]

        targets = []

        if mode == "single":
            target = data.get("target", "").strip()
            if target:
                targets = [target]

        elif mode == "bulk":
            ip_range = data.get("ip_range", "").strip()
            cidr_value = data.get("cidr", "").strip()

            if "-" in ip_range:
                range_targets = IP_Ranger(*map(str.strip, str(ip_range).split("-")))
                targets.extend(range_targets)
            if cidr_value:
                #print(cidr_value)
                for j in cidr_value.splitlines():
                    j = j.strip()
                    #print(j)
                    try:
                        net = ip_network(j)
                        hosts = list(net.hosts())
                        if not hosts:
                            targets.extend([str(ip) for ip in net])
                        else:
                            targets.extend([str(ip) for ip in hosts])
                    except ValueError as e:
                        await websocket.send_json({"type": "error", "message": f"Invalid CIDR format: {e}"})
                        return

            file_lines = data.get("file_lines", [])
            file_lines = [line.strip() for line in file_lines if line.strip()]
            targets.extend(file_lines)

        targets = list(set(filter(None, targets)))
        if not targets:
            await websocket.send_json({"status": "done", "message": "No valid targets"})
            return

        total_targets = len(targets)
        completed = 0
        open_ports_count = 0
        closed_ports_count = 0
        port_frequency = {}

        scan_tasks = [THREAD_PORTSCAN(ip, ports_) for ip in targets]

        for task in asyncio.as_completed(scan_tasks):
            if scan_cancel_event.is_set():
                await websocket.send_json({"status": "stopped"})
                return

            result = await task
            completed += 1

            open_ports_count += len(result["open_ports"])
            closed_ports_count += len(result["closed_ports"])

            for port in result["open_ports"]:
                port_frequency[str(port)] = port_frequency.get(str(port), 0) + 1

            new_line = f"Target: {result['target']} | Open: {result['open_ports']} | Closed: {result['closed_ports']}"

            await websocket.send_json({
                "progress_done": completed,
                "progress_total": total_targets,
                "open_ports": open_ports_count,
                "closed_ports": closed_ports_count,
                "top_ports": port_frequency,
                "new_result_line": new_line,
                "status": "running"
            })

        await websocket.send_json({"status": "done"})

    try:
        while True:
            data = await websocket.receive_json()

            command = data.get("command", "start")  # command "start" or "stop"

            if command == "start":
                if scan_task and not scan_task.done():
                    await websocket.send_json({"type": "error", "message": "Scan already running"})
                    continue
                scan_cancel_event.clear()
                scan_task = asyncio.create_task(fire_scanner(data))

            elif command == "stop":
                if scan_task and not scan_task.done():
                    scan_cancel_event.set()
                    await scan_task  # wait clean up
                else:
                    await websocket.send_json({"type": "error", "message": "No scan is running"})

    except WebSocketDisconnect:
        #print("WebSocket WebSocketDisconnect")
        if scan_task and not scan_task.done():
            scan_cancel_event.set()
            await scan_task

    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})


@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)  

if __name__ == "__main__":
    try:
        os.makedirs('Success_Results', exist_ok=True)  # fixed here
    except Exception as e:
        print(f"Error Created Folder Success_Results: {e}")
    print('[+] Thread Running :', max_threads)
    uvicorn.run("main:app", host="localhost", port=8000, reload=True, log_level="debug")