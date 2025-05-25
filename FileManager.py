import os
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Union, Optional
import psutil


@dataclass
class FileMeta:
    size: int  # 文件大小(字节)
    created: float  # 创建时间戳(time.time())
    modified: float  # 最后修改时间戳
    permissions: str  # Unix风格权限字符串(如"rw-r--r--")
    owner: str  # 文件所有者用户名


@dataclass
class ProcessFileInfo:  # 描述进程打开的文件信息
    pid: int  # 进程ID
    fd: int  # 文件描述符
    path: str  # 文件路径
    mode: str  # 访问模式
    position: int  # 文件指针位置


class SimulatedFileSystem:  # 初始化文件系统结构
    def __init__(self):
        self.fs = defaultdict(dict)  # 文件系统树结构,创建自动初始化嵌套字典的结构
        self.current_dir = ["C:"]  # 当前工作目录
        self.open_files = {}  # 打开文件表
        self.users = {"root": "admin", "user1": "password"}  # 用户数据库
        self.current_user = "root"  # 当前登录用户(默认root)

        # 初始化根目录
        self._create_dir(["C:"], FileMeta(
            size=0,
            created=time.time(),
            modified=time.time(),
            permissions="rwxr-xr-x",
            owner="root"
        ))

    def _get_full_path(self, path: List[str]) -> List[str]:
        """解析相对/绝对路径"""
        if not path:  # 空路径返回当前目录
            return self.current_dir.copy()  # 返回副本避免修改原列表
        if path[0].endswith(":"):  # 绝对路径判断(以盘符结尾)
            return path
        return self.current_dir + path  # 相对路径=当前目录+参数路径

    def _create_dir(self, path: List[str], meta: FileMeta):
        """内部目录创建方法"""
        current = self.fs  # 从根开始
        for part in path[:-1]:  # 遍历除最后部分外的所有路径
            current = current.setdefault(part, {})  # 不存在则创建空字典
        current[path[-1]] = {  # 设置最终目录节点
            "_meta": meta,  # 存储元数据
            "_type": "dir"  # 标记为目录类型
        }

    def mkdir(self, dirname: str):
        """创建目录"""
        path = self._get_full_path([dirname])
        parent_path = path[:-1]

        # 检查父目录是否存在
        parent = self.fs
        for part in parent_path:
            if part not in parent or parent[part].get("_type") != "dir":
                raise FileNotFoundError(f"Parent directory not found: {'/'.join(parent_path)}")
            parent = parent[part]

        # 检查目录是否已存在
        if dirname in parent:
            raise FileExistsError(f"Directory already exists: {'/'.join(path)}")

        self._create_dir(path, FileMeta(
            size=0,
            created=time.time(),
            modified=time.time(),
            permissions="rwxr-xr-x",
            owner=self.current_user
        ))
        print(f"Directory created: {'/'.join(path)}")

    def create_file(self, filename: str, content: str = ""):
        """创建文件"""
        path = self._get_full_path([filename])
        parent_path = path[:-1]

        # 检查父目录
        parent = self.fs
        for part in parent_path:
            if part not in parent or parent[part].get("_type") != "dir":
                raise FileNotFoundError(f"Parent directory not found: {'/'.join(parent_path)}")
            parent = parent[part]

        # 检查文件是否存在
        if filename in parent:
            raise FileExistsError(f"File already exists: {'/'.join(path)}")

        parent[filename] = {
            "_type": "file",
            "_meta": FileMeta(
                size=len(content),
                created=time.time(),
                modified=time.time(),
                permissions="rw-r--r--",
                owner=self.current_user
            ),
            "content": content
        }
        print(f"File created: {'/'.join(path)} (Size: {len(content)} bytes)")

    def delete_file(self, filename: str):
        """删除指定文件"""
        path = self._get_full_path([filename])
        current = self.fs

        # 导航到文件所在目录
        for part in path[:-1]:
            if part not in current or current[part].get("_type") != "dir":
                raise FileNotFoundError(f"Path not found: {'/'.join(path[:-1])}")
            current = current[part]

        # 检查目标是否是文件
        if path[-1] not in current or current[path[-1]].get("_type") != "file":
            raise FileNotFoundError(f"File not found: {'/'.join(path)}")

        # 检查权限（简单实现，实际应该检查权限位）
        if current[path[-1]]["_meta"].owner != self.current_user:
            raise PermissionError("Permission denied: You don't own this file")

        # 从文件系统中删除
        del current[path[-1]]
        print(f"File deleted: {'/'.join(path)}")

    def open_file(self, filename: str, mode: str = "r") -> int:
        """打开文件并返回文件描述符"""
        content = self.read_file(filename)  # 会验证文件是否存在
        fd = len(self.open_files) + 1  # 简单的文件描述符生成
        self.open_files[fd] = {
            "filename": filename,
            "mode": mode,
            "position": 0  # 文件指针位置
        }
        return fd

    def close_file(self, fd: int):
        """关闭已打开的文件"""
        if fd not in self.open_files:
            raise ValueError(f"Invalid file descriptor: {fd}")

        filename = self.open_files[fd]["filename"]
        del self.open_files[fd]
        print(f"Closed file: {filename} (fd: {fd})")

    def ls(self, path: List[str] = None):
        """列出目录内容"""
        target = self._get_full_path(path or [])
        current = self.fs

        for part in target:
            if part not in current or current[part].get("_type") != "dir":
                raise FileNotFoundError(f"Directory not found: {'/'.join(target)}")
            current = current[part]

        print(f"Contents of {'/'.join(target)}:")
        for name, data in current.items():
            if name.startswith("_"): continue
            meta = data["_meta"]
            print(f"{data['_type'][0]} {meta.permissions} {meta.owner:>8} {meta.size:>6} {name}")

    def cd(self, path: List[str]):
        """切换工作目录"""
        target = self._get_full_path(path)
        current = self.fs

        for part in target:
            if part not in current or current[part].get("_type") != "dir":
                raise FileNotFoundError(f"Directory not found: {'/'.join(target)}")
            current = current[part]

        self.current_dir = target
        print(f"Current directory: {'/'.join(self.current_dir)}")

    def cd_up(self):
        """返回上一级目录"""
        if len(self.current_dir) <= 1:  # 已经在根目录(C:)
            print("Already at root directory")
            return

        self.current_dir = self.current_dir[:-1]  # 移除最后一级
        print(f"Current directory: {'/'.join(self.current_dir)}")

    def read_file(self, filename: str) -> str:
        """读取文件内容"""
        path = self._get_full_path([filename])
        current = self.fs

        for part in path[:-1]:
            if part not in current or current[part].get("_type") != "dir":
                raise FileNotFoundError(f"Path not found: {'/'.join(path[:-1])}")
            current = current[part]

        if path[-1] not in current or current[path[-1]].get("_type") != "file":
            raise FileNotFoundError(f"File not found: {'/'.join(path)}")

        return current[path[-1]]["content"]

    def write_file(self, filename: str, content: str, mode: str = "w"):
        """写入文件内容"""
        path = self._get_full_path([filename])
        current = self.fs

        for part in path[:-1]:
            if part not in current or current[part].get("_type") != "dir":
                raise FileNotFoundError(f"Path not found: {'/'.join(path[:-1])}")
            current = current[part]

        if path[-1] not in current or current[path[-1]].get("_type") != "file":
            raise FileNotFoundError(f"File not found: {'/'.join(path)}")

        file_data = current[path[-1]]
        if mode == "w":
            file_data["content"] = content
        elif mode == "a":
            file_data["content"] += content
        else:
            raise ValueError("Invalid mode. Use 'w' (write) or 'a' (append)")

        # 更新元数据
        file_data["_meta"].size = len(file_data["content"])
        file_data["_meta"].modified = time.time()

        print(f"Written {len(content)} bytes to {'/'.join(path)}")

    def get_process_file_args(self, pid: int = None) -> dict:
            """
            获取进程打开的文件参数信息

            参数:
                pid: 可选，指定进程ID。如果为None，则返回所有进程的信息

            返回:
                字典: {pid: [文件信息, ...]}
                文件信息格式: {
                    'fd': 文件描述符,
                    'path': 文件路径,
                    'mode': 访问模式,
                    'position': 文件指针位置
                }
            """
            result = {}

            # 1. 获取模拟文件系统中打开的文件
            if pid is None or pid == os.getpid():
                proc_files = []
                for fd, file_info in self.open_files.items():
                    proc_files.append({
                        'fd': fd,
                        'path': '/'.join(self._get_full_path([file_info["filename"]])),
                        'mode': file_info["mode"],
                        'position': file_info["position"]
                    })
                if proc_files:
                    result[os.getpid()] = proc_files

            # 2. 获取真实系统中进程打开的文件
            try:
                for proc in psutil.process_iter(['pid', 'open_files']):
                    if pid is not None and proc.pid != pid:
                        continue

                    files = []
                    # 添加模拟系统打开的文件
                    if proc.pid == os.getpid() and os.getpid() in result:
                        files.extend(result[os.getpid()])

                    # 添加真实系统打开的文件
                    if hasattr(proc, 'open_files') and proc.open_files():
                        for f in proc.open_files():
                            files.append({
                                'fd': f.fd,
                                'path': f.path,
                                'mode': self._get_file_mode(f.path),
                                'position': 0  # 真实系统中无法获取，设为0
                            })

                    if files:
                        result[proc.pid] = files
            except (ImportError, psutil.Error) as e:
                print(f"获取真实进程文件错误: {str(e)}")

            return result

    def _get_file_mode(self, path: str) -> str:
            """辅助方法: 获取文件的访问模式"""
            try:
                if os.access(path, os.R_OK | os.W_OK):
                    return "rw"
                elif os.access(path, os.R_OK):
                    return "r"
                elif os.access(path, os.W_OK):
                    return "w"
            except:
                pass
            return "u"  # unknown

    def login(self, username: str, password: str):
        """用户登录"""
        if username in self.users and self.users[username] == password:
            self.current_user = username
            print(f"Logged in as {username}")
        else:
            raise PermissionError("Invalid credentials")
