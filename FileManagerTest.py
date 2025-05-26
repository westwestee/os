import os

from FileManager import FileManager
from ProcessManager import ProcessManager
from MemoryManager import MemoryManager
from DeviceManager import DeviceManager


def main():

    # 初始化依赖模块
    process_mgr = ProcessManager()
    memory_mgr = MemoryManager()
    device_mgr = DeviceManager()

    # 创建 FileManager 实例并注入依赖
    fs = FileManager(process_mgr, memory_mgr, device_mgr)
    logged_in = False
    open_files = {}  # 跟踪打开的文件描述符
    memory_mappings = {}  # 跟踪内存映射 {虚拟地址: fd}

    print("欢迎使用增强版模拟文件系统")
    print("基础命令: login, logout, mkdir, cd, create_file, write_file, read_file, ls, exit")
    print("文件操作: delete_file, open_file, close_file, list_open_files")
    print("高级功能: mmap, munmap, swap_stats, block_io")

    while True:
        command = input("\n> ").strip().split()
        if not command:
            continue

        cmd = command[0].lower()
        args = command[1:]

        try:
            if cmd == "login":
                if len(args) != 2:
                    print("用法: login 用户名 密码")
                    continue
                fs.login(args[0], args[1])
                logged_in = True
                print(f"用户 {args[0]} 登录成功")

            elif cmd == "logout":
                fs.current_user = "root"
                logged_in = False
                # 关闭所有打开的文件和内存映射
                for fd in list(open_files.keys()):
                    fs.close_file(fd)
                    open_files.pop(fd)
                memory_mappings.clear()
                print("已注销")

            elif not logged_in:
                print("请先登录后再执行操作")

            elif cmd == "mkdir":
                if not args:
                    print("用法: mkdir 目录名")
                    continue
                fs.mkdir(args[0])
                print(f"目录 {args[0]} 创建成功")

            elif cmd == "cd":
                fs.cd(args)
                print(f"当前目录: {'/'.join(fs.current_dir)}")

            elif cmd in ("cd_up", "cd.."):
                fs.cd_up()

            elif cmd == "create_file":
                if len(args) < 1:
                    print("用法: create_file 文件名 [内容]")
                    continue
                content = " ".join(args[1:]) if len(args) > 1 else ""
                fs.create_file(args[0], content)
                print(f"文件 {args[0]} 创建成功")

            elif cmd == "write_file":
                if len(args) < 2:
                    print("用法: write_file 文件名 内容 [mode=a]")
                    continue
                mode = args[-1] if args[-1] in ("w", "a") else "a"
                content = " ".join(args[1:-1]) if args[-1] in ("w", "a") else " ".join(args[1:])
                fs.write_file(args[0], content, mode=mode)
                print(f"文件 {args[0]} 写入成功")

            elif cmd == "read_file":
                if not args:
                    print("用法: read_file 文件名")
                    continue
                print(fs.read_file(args[0]))

            elif cmd == "ls":
                fs.ls(args)

            elif cmd == "delete_file":
                if not args:
                    print("用法: delete_file 文件名")
                    continue
                fs.delete_file(args[0])
                print(f"文件 {args[0]} 已删除")
                # 如果文件是打开的，关闭它
                for fd, file_info in list(open_files.items()):
                    if file_info["filename"] == args[0]:
                        fs.close_file(fd)
                        open_files.pop(fd)

            elif cmd == "open_file":
                if len(args) < 1:
                    print("用法: open_file 文件名 [模式=r|w|a]")
                    continue
                mode = args[1] if len(args) > 1 else "r"
                fd = fs.open_file(args[0], mode)
                open_files[fd] = {"filename": args[0], "mode": mode}
                print(f"文件 {args[0]} 已打开，文件描述符: {fd}")

            elif cmd == "close_file":
                if not args:
                    print("用法: close_file 文件描述符")
                    continue
                try:
                    fd = int(args[0])
                except ValueError:
                    print("错误: 文件描述符必须是整数")
                    continue

                if fd not in open_files:
                    print(f"错误: 文件描述符 {fd} 未找到")
                    continue

                fs.close_file(fd)
                open_files.pop(fd)
                print(f"文件描述符 {fd} 已关闭")

            elif cmd == "list_open_files":

                if len(args) > 1:
                    print("用法: list_open_files [pid]")

                    continue

                try:

                    pid = int(args[0]) if args else None

                    open_files = fs.get_process_file_args(pid)

                    if not open_files:

                        print("没有找到打开的文件")

                    else:

                        for process_id, files in open_files.items():

                            print(f"\n进程 {process_id} 打开的文件:")

                            for f in files:
                                print(f"  文件描述符 {f['fd']}: {f['path']}")

                                print(f"  访问模式: {f['mode']}, 指针位置: {f['position']}")

                except ValueError:

                    print("错误: PID必须是整数")

                    # ========================
                    # 新增高级功能命令
                    # ========================
            elif cmd == "mmap":
                """用法: mmap <fd> <虚拟地址>"""
                if len(args) != 2:
                    print("错误: 参数数量不正确")
                    print("用法: mmap <文件描述符> <虚拟地址(十六进制)>")
                    print("示例: mmap 1 0x4000")
                    continue

                try:
                    fd = int(args[0])
                    virt_addr = int(args[1], 16)
                except ValueError:
                    print("错误: 参数格式无效")
                    print("文件描述符必须是整数，虚拟地址应为十六进制格式（如 0x4000）")
                    continue

                if fd not in open_files:
                    print(f"错误: 文件描述符 {fd} 未打开或不存在")
                    continue

                if virt_addr in memory_mappings:
                    print(f"错误: 虚拟地址 0x{virt_addr:X} 已被占用")
                    continue

                try:
                    result = fs.mmap_file(os.getpid(), fd, virt_addr)
                    if result == 0:
                        memory_mappings[virt_addr] = fd
                        print(f"映射成功: 文件描述符 {fd} -> 虚拟地址 0x{virt_addr:X}")
                    else:
                        error_map = {
                            -9: "错误: 文件描述符无效 (EBADF)",
                            -12: "错误: 内存不足 (ENOMEM)",
                            -22: "错误: 参数无效 (EINVAL)"
                        }
                        print(error_map.get(result, f"未知错误，错误码: {result}"))
                except Exception as e:
                    print(f"映射过程中发生异常: {str(e)}")

            elif cmd == "munmap":
                """用法: munmap <虚拟地址>"""
                if len(args) != 1:
                    print("用法: munmap 虚拟地址(十六进制)")
                    continue
                try:
                    virt_addr = int(args[0], 16)
                except ValueError:
                    print("错误: 地址必须是十六进制")
                    continue

                if virt_addr not in memory_mappings:
                    print("错误: 该地址未映射")
                    continue

                # 调用内存管理接口解除映射（需在 MemoryManager 实现 unmap）
                fs.memory_mgr.unmap_memory(os.getpid(), virt_addr)
                del memory_mappings[virt_addr]
                print(f"虚拟地址 0x{virt_addr:X} 的映射已解除")



            elif cmd == "block_io":
                """用法: block_io <read/write> <设备ID> <LBA> [数据]"""
                if len(args) < 3:
                    print("错误: 参数不足")
                    print("用法: block_io <read/write> 设备ID LBA [数据(写操作时)]")
                    continue
                # 解析操作类型、设备ID和LBA
                op = args[0].lower()
                try:
                    device_id = int(args[1])
                    lba = int(args[2])
                except ValueError:
                    print("错误: 设备ID和LBA必须是整数")
                    continue
                # 处理数据（写操作需要数据）
                data = None
                if op == "write":
                    if len(args) < 4:
                        print("错误: 写操作需要提供数据")
                        continue
                    data = bytes(" ".join(args[3:]), "utf-8")  # 将参数合并为字节数据
                # 调用设备管理模块
                try:
                    if op == "read":
                        result = fs.block_io("read", device_id, lba, None)
                        if isinstance(result, bytes):
                            print(f"读取成功: 设备 {device_id} LBA {lba} 数据: {result[:64]}...")
                        else:
                            print(f"读取失败，错误码: {result}")
                    elif op == "write":
                        result = fs.block_io("write", device_id, lba, data)
                        if result == 0:
                            print(f"写入成功: 设备 {device_id} LBA {lba}")
                        else:
                            print(f"写入失败，错误码: {result}")
                    else:
                        print("错误: 操作类型必须是 read 或 write")
                except Exception as e:
                    print(f"操作异常: {str(e)}")

            elif cmd == "swap_stats":
                """显示当前交换状态"""
                print("当前内存映射关系:")
                for virt_addr, fd in memory_mappings.items():
                    print(f"  虚拟地址 0x{virt_addr:X} -> 文件描述符 {fd}")

            elif cmd == "exit":
                # 关闭所有打开的文件
                for fd in list(open_files.keys()):
                    fs.close_file(fd)
                    open_files.pop(fd)
                print("退出系统")
                break

            else:
                print("未知命令")
                print("可用命令: login, logout, mkdir, cd, create_file, write_file, read_file, ls, exit")
                print("新增命令: delete_file, open_file, close_file, list_open_files")

        except Exception as e:
            print(f"错误: {str(e)}")


if __name__ == "__main__":
    main()
