from moni import SimulatedFileSystem


def main():
    fs = SimulatedFileSystem()
    logged_in = False
    open_files = {}  # 跟踪打开的文件描述符

    print("欢迎使用模拟文件系统")
    print("可用命令: login, logout, mkdir, cd, create_file, write_file, read_file, ls, exit")
    print("新增命令: delete_file, open_file, close_file, list_open_files")

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
                fs.logout()
                logged_in = False
                # 关闭所有打开的文件
                for fd in list(open_files.keys()):
                    fs.close_file(fd)
                    open_files.pop(fd)
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
