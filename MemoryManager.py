from collections import defaultdict


class MemoryManager:
    def __init__(self):
        self.page_table = defaultdict(dict)  # 确保实例属性存在

    def map_memory(self, pid: int, virtual_addr: int, size: int, flags: str) -> None:
        """实例方法：映射虚拟内存到物理内存"""
        if pid not in self.page_table:
            self.page_table[pid] = {}
        self.page_table[pid][virtual_addr] = {
            "physical_addr": None,  # 实际需要分配物理地址
            "size": size,
            "flags": flags
        }

    def unmap_memory(self, pid: int, virtual_addr: int) -> None:
        """解除内存映射"""
        if pid in self.page_table and virtual_addr in self.page_table[pid]:
            del self.page_table[pid][virtual_addr]
