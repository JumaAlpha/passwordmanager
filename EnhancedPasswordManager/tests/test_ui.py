import unittest
from src.ui import UserInterface

class TestUserInterface(unittest.TestCase):
    def setUp(self):
        self.ui = UserInterface()

    def test_display_main_window(self):
        # Test the main window display logic
        self.assertTrue(self.ui.display_main_window())

if __name__ == "__main__":
    unittest.main()
