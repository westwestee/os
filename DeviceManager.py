from collections import defaultdict

class DeviceManager:
    def __init__(self):
        # 存储结构: {设备ID: {LBA: 数据}}
        self.storage = defaultdict(lambda: defaultdict(bytes))

    def read_block(self, device_id: int, lba: int) -> bytes:
        """读取块设备数据（模拟512字节块）"""
        # 未初始化的块返回空数据
        return self.storage[device_id].get(lba, b"\x00" * 512)

    def write_block(self, device_id: int, lba: int, data: bytes) -> int:
        """写入块设备数据（自动填充到512字节）"""
        # 确保数据长度为512字节（不足部分填充0x00）
        aligned_data = data.ljust(512, b"\x00")
        self.storage[device_id][lba] = aligned_data
        return 0  # 返回成功状态
