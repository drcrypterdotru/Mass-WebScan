from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
import asyncio
import socket
from ipaddress import ip_address, ip_network
import concurrent.futures
import multiprocessing
import uvicorn
import os



app = FastAPI()
PORT_TIMEOUT = 5

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")
else:
    print("[!] Warning: 'static/' directory not found")

max_threads = multiprocessing.cpu_count() * 4
executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_threads)

def DATA_SAVE(result, filename):
    with open(f'Success_Results/{filename}', "a") as save:
        save.write(f'{result}\n')

async def scan_ports_threaded(host, ports=[21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 8080, 8443]):
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
        if Port_Success :
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

            # IP range
            if "-" in ip_range:
                try:
                    range_targets = IP_Ranger(*map(str.strip, ip_range.split("-")))
                    targets.extend(range_targets)
                except Exception as e:
                    await websocket.send_json({"type": "error", "message": f"Invalid IP range: {e}"})
                    return


            if cidr_value:
                for cidr_line in cidr_value.splitlines():
                    cidr_line = cidr_line.strip()
                    if not cidr_line:
                        continue
                    try:
                        net = ip_network(cidr_line, strict=False)
                        ips = list(net.hosts())
                        if not ips:
                            ips = list(net)

                        
                        targets_cidr = [str(ip) for ip in ips]
                        total_targets = len(targets_cidr)
                        completed = 0
                        open_ports_count = 0
                        closed_ports_count = 0
                        top_ported = {}

                        print(f'[DEBUG] Found {cidr_line} ==>',total_targets)

                        scan_tasks = [scan_ports_threaded(ip, ports_) for ip in targets_cidr]
                        print(f"[DEBUG] START CIDR : {len(scan_tasks)}")
                        for task in asyncio.as_completed(scan_tasks):
                            
                
                            if scan_cancel_event.is_set():
                                await websocket.send_json({"status": "stopped"})
                                return

                            result = await task
                            completed += 1

                            open_ports_count += len(result["open_ports"])
                            closed_ports_count += len(result["closed_ports"])

                            for port in result["open_ports"]:
                                top_ported[str(port)] = top_ported.get(str(port), 0) + 1

                            new_line = f"Target: {result['target']} | Open: {result['open_ports']} | Closed: {result['closed_ports']}"

                            await websocket.send_json({
                                "progress_done": completed,
                                "progress_total": total_targets,
                                "open_ports": open_ports_count,
                                "closed_ports": closed_ports_count,
                                "top_ports": top_ported,
                                "new_result_line": new_line,
                                "status": "running",
                                "current_cidr": cidr_line
                            })

                    except ValueError as e:
                        await websocket.send_json({"type": "error", "message": f"Invalid CIDR format: {e}"})
                        return

        
        # file_lines = data.get("file_lines", [])
        # file_lines = [line.strip() for line in file_lines if line.strip()]
        # targets.extend(file_lines)

        
        targets = list(set(filter(None, targets)))

        if not targets:
            await websocket.send_json({"status": "done", "message": "No valid targets"})
            return

        total_targets = len(targets)
        completed = 0
        open_ports_count = 0
        closed_ports_count = 0
        top_ported = {}

        
        scan_tasks = [scan_ports_threaded(ip, ports_) for ip in targets]
        print(f"[DEBUG] START Ranger : {len(scan_tasks)}")
        for task in asyncio.as_completed(scan_tasks):
            if scan_cancel_event.is_set():
                await websocket.send_json({"status": "stopped"})
                return

            result = await task
            completed += 1

            open_ports_count += len(result["open_ports"])
            closed_ports_count += len(result["closed_ports"])

            for port in result["open_ports"]:
                top_ported[str(port)] = top_ported.get(str(port), 0) + 1

            new_line = f"Target: {result['target']} | Open: {result['open_ports']} | Closed: {result['closed_ports']}"

            await websocket.send_json({
                "progress_done": completed,
                "progress_total": total_targets,
                "open_ports": open_ports_count,
                "closed_ports": closed_ports_count,
                "top_ports": top_ported,
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
        if scan_task and not scan_task.done():
            scan_cancel_event.set()
            await scan_task

    except Exception as e:
        await websocket.send_json({"type": "error", "message": str(e)})

@app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)

if __name__ == "__main__":
    # create Folder Success_Results
    try:
        os.makedirs('Success_Results', exist_ok=True)
    except:
        pass 
    
    print(f"[+] Starting scanner with {max_threads} threads")
    #START APP
    uvicorn.run("main:app", host="localhost", port=8000, reload=True, log_level="debug")
