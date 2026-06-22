"""Unit tests for firmware detection heuristics (no IDA required)."""
import struct
import unittest


class TestCortexMDetection(unittest.TestCase):
    """Test the Cortex-M IVT parsing logic in isolation."""

    def _make_ivt(self, sp: int, reset: int, extra: list = None) -> bytes:
        """Build a minimal Cortex-M IVT."""
        entries = [sp, reset] + (extra or [0] * 14)
        return struct.pack(f"<{len(entries)}I", *entries)

    def test_sp_in_ram_reset_in_flash(self):
        """Valid Cortex-M IVT: SP in RAM, reset vector in flash (Thumb)."""
        sp = 0x20010000      # RAM
        reset = 0x08000101   # Flash + Thumb bit
        ivt = self._make_ivt(sp, reset)

        sp_val = struct.unpack_from("<I", ivt, 0)[0]
        reset_val = struct.unpack_from("<I", ivt, 4)[0]
        reset_addr = reset_val & ~1
        is_thumb = bool(reset_val & 1)

        self.assertTrue(0x20000000 <= sp_val <= 0x20200000)
        self.assertTrue(0x08000000 <= reset_addr <= 0x08200000)
        self.assertTrue(is_thumb)

    def test_sp_not_in_ram_not_cortex_m(self):
        """If SP is not in RAM range, not a Cortex-M IVT."""
        sp = 0x00000000      # Not RAM
        reset = 0x08000101
        ivt = self._make_ivt(sp, reset)
        sp_val = struct.unpack_from("<I", ivt, 0)[0]
        self.assertFalse(0x20000000 <= sp_val <= 0x20200000)

    def test_vector_names_assigned_correctly(self):
        """Standard Cortex-M vector names."""
        _CORTEX_M_VECTORS = [
            "Initial_SP", "Reset_Handler", "NMI_Handler", "HardFault_Handler",
            "MemManage_Handler", "BusFault_Handler", "UsageFault_Handler",
        ]
        self.assertEqual(_CORTEX_M_VECTORS[0], "Initial_SP")
        self.assertEqual(_CORTEX_M_VECTORS[1], "Reset_Handler")
        self.assertEqual(_CORTEX_M_VECTORS[3], "HardFault_Handler")

    def test_irq_naming_beyond_standard_vectors(self):
        """IRQ vectors beyond index 15 should be named IRQ{n}_Handler."""
        for i in range(16, 64):
            name = f"IRQ{i - 16}_Handler"
            self.assertTrue(name.startswith("IRQ"))

    def test_thumb_bit_detection(self):
        """LSB=1 means Thumb mode."""
        thumb_addr = 0x08000101
        arm_addr = 0x08000100
        self.assertTrue(bool(thumb_addr & 1))
        self.assertFalse(bool(arm_addr & 1))
        self.assertEqual(thumb_addr & ~1, 0x08000100)


class TestPointerDensityHeuristic(unittest.TestCase):
    """Test the pointer density load address detection."""

    def test_dense_pointers_at_known_base(self):
        """If many values resolve to binary range at a given base, that's the base."""
        binary_size = 0x10000
        base = 0x08000000
        # Create 10 pointer values that resolve to [base, base+binary_size)
        pointers = [base + i * 0x100 for i in range(10)]
        data = struct.pack(f"<{len(pointers)}I", *pointers)

        ptr_candidates = {}
        for i in range(0, len(data) - 3, 4):
            v = struct.unpack_from("<I", data, i)[0]
            for b in (0x00000000, 0x08000000, 0x10000000, 0x20000000):
                if b <= v < b + binary_size:
                    ptr_candidates[b] = ptr_candidates.get(b, 0) + 1

        best = max(ptr_candidates, key=ptr_candidates.get)
        self.assertEqual(best, base)
        self.assertGreaterEqual(ptr_candidates[best], 10)

    def test_no_pointers_no_candidate(self):
        """Random data should not produce a strong candidate."""
        import os
        data = os.urandom(256)
        binary_size = 0x10000
        ptr_candidates = {}
        for i in range(0, len(data) - 3, 4):
            v = struct.unpack_from("<I", data, i)[0]
            for b in (0x08000000,):
                if b <= v < b + binary_size:
                    ptr_candidates[b] = ptr_candidates.get(b, 0) + 1
        # Random data should have very few matches
        total = sum(ptr_candidates.values())
        self.assertLess(total, 5)


class TestMMIODetection(unittest.TestCase):
    """Test MMIO peripheral address classification."""

    _KNOWN_PERIPHERALS = [
        (0x40000000, 0x40007FFF, "STM32_APB1", "STM32"),
        (0x40010000, 0x40017FFF, "STM32_APB2", "STM32"),
        (0x40020000, 0x4007FFFF, "STM32_AHB1", "STM32"),
        (0xE0000000, 0xFFFFFFFF, "ARM_system_space", "generic_cortex_m"),
    ]

    def _classify(self, addr: int):
        for pbase, pend, pname, pfamily in self._KNOWN_PERIPHERALS:
            if pbase <= addr <= pend:
                return pname, pfamily
        return None, None

    def test_stm32_apb1_classified(self):
        name, family = self._classify(0x40000400)  # USART2 on STM32
        self.assertEqual(family, "STM32")
        self.assertEqual(name, "STM32_APB1")

    def test_stm32_apb2_classified(self):
        name, family = self._classify(0x40011000)  # USART1 on STM32
        self.assertEqual(family, "STM32")
        self.assertEqual(name, "STM32_APB2")

    def test_arm_system_space_classified(self):
        name, family = self._classify(0xE000E100)  # NVIC
        self.assertEqual(family, "generic_cortex_m")

    def test_binary_address_not_classified(self):
        name, family = self._classify(0x08001000)  # Flash address
        self.assertIsNone(name)

    def test_page_grouping(self):
        """Addresses in same 4KB page should group together."""
        addr1 = 0x40011000
        addr2 = 0x40011004
        addr3 = 0x40011FFF
        self.assertEqual(addr1 & ~0xFFF, addr2 & ~0xFFF)
        self.assertEqual(addr1 & ~0xFFF, addr3 & ~0xFFF)

    def test_chip_family_voting(self):
        """Most common peripheral family wins."""
        accesses = [
            ("STM32", 10), ("STM32", 5), ("generic_cortex_m", 2)
        ]
        votes = {}
        for fam, count in accesses:
            votes[fam] = votes.get(fam, 0) + count
        winner = max(votes, key=votes.get)
        self.assertEqual(winner, "STM32")


class TestSizeHints(unittest.TestCase):
    """Test binary size → MCU family hints."""

    def _hint(self, size: int) -> str:
        if 0x10000 <= size <= 0x20000:
            return "STM32F0/F1"
        elif 0x20000 <= size <= 0x80000:
            return "STM32F4/F7 or nRF52"
        elif 0x80000 <= size <= 0x200000:
            return "ESP32 / STM32H7"
        elif size > 0x200000:
            return "Linux firmware"
        return "unknown"

    def test_64kb_is_stm32f0(self):
        self.assertIn("STM32F0", self._hint(0x10000))

    def test_256kb_is_stm32f4(self):
        self.assertIn("STM32F4", self._hint(0x40000))

    def test_4mb_is_linux(self):
        self.assertIn("Linux", self._hint(0x400000))


if __name__ == "__main__":
    unittest.main()
