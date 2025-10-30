#!/usr/bin/env python3
"""
Screen Tearing Stress Test Application

This application is designed to exacerbate screen tearing by creating various
visual patterns that are particularly susceptible to tearing artifacts.
It uses the lib/application as the base for window creation and rendering.
"""

import math
import time
import pyray as rl
from openpilot.common.realtime import config_realtime_process
from openpilot.system.ui.lib.application import FontWeight, gui_app
from openpilot.system.ui.widgets.scroller import Scroller
from openpilot.system.ui.widgets.label import Label


class ScreenTearingStressTest:
    """Stress test application designed to exacerbate screen tearing."""

    def __init__(self):
        self.time_offset = 0.0
        self.test_mode = 0
        self.speed_multiplier = 1.0
        self.line_thickness = 2
        self.color_cycle_speed = 1.0
        self.animation_time = 0.0
        self.color_offset = 0.0
        self.last_pattern_change = 0.0
        self.pattern_duration = 30.0  # 30 seconds per pattern
        self.text_scroller = None

        # Test patterns data (order: horizontal, text scrolling, then others)
        self.patterns = [
            "Horizontal Lines",
            "Text Scrolling",
            "Vertical Lines",
            "Diagonal Lines",
            "Rotating Squares",
            "Pulsing Circles",
        ]

    def _setup_text_scroller(self):
        """Setup the text scroller widget with firehose-style content."""
        text_lines = [
            "SCREEN TEARING TEST - VERTICAL SCROLLING TEXT PATTERN",
            "This comprehensive pattern tests text rendering performance and helps identify tearing artifacts",
            "Watch carefully for horizontal lines or stuttering as you scroll through this text content",
            "Text rendering is often a significant source of screen tearing issues in real applications",
            "This test uses multiple font sizes and colors to stress the text rendering system effectively",
            "The scrolling motion makes it very easy to spot any tearing or frame drops that occur",
            "Each line has different properties to test various text rendering scenarios and edge cases",
            "High-frequency text updates can cause significant tearing on some systems and hardware",
            "This is particularly common in automotive displays and embedded systems with limited resources",
            "The scrolling text pattern is specifically designed to maximize the visibility of tearing artifacts",
            "Continue scrolling to test different aspects of the text rendering pipeline and performance",
            "Multiple lines help identify whether tearing affects individual characters, entire lines, or blocks",
            "This comprehensive test should reveal any text-related tearing issues in production applications",
            "The wide text content provides better coverage and makes horizontal tearing more apparent",
            "Centered text positioning ensures the pattern is clearly visible across the entire screen width",
            "Vertical scrolling motion is ideal for detecting horizontal tearing lines in text rendering",
            "Text-based tearing is often more noticeable than geometric pattern tearing in real UIs",
            "This pattern specifically targets the text rendering subsystem for comprehensive testing",
            "The continuous scrolling motion creates a consistent visual flow for tearing detection",
            "Wide text lines provide maximum horizontal coverage to catch any tearing artifacts",
            "This test pattern is optimized for identifying text-related screen tearing issues",
            "Use mouse wheel or drag to scroll through this content and look for tearing artifacts",
            "The firehose-style widget allows you to control the scrolling speed and direction",
            "This gives you better control over the test conditions for identifying specific tearing issues",
            "Scroll slowly to examine individual lines, or scroll quickly to test rapid text updates",
            "The text content is designed to stress different aspects of the text rendering pipeline",
            "Look for horizontal lines, stuttering, or other visual artifacts as you scroll",
            "This pattern is particularly effective at catching text-related tearing in UI applications",
            "The scrollable content provides a realistic test scenario for text-heavy applications",
            "Continue scrolling to test the full range of text rendering performance characteristics"
        ]

        text_widgets = []
        for i, line in enumerate(text_lines):
            font_size = 36 + (i % 3) * 12  # 36, 48, 60
            text_widgets.append(Label(line, font_size=font_size))

        self.text_scroller = Scroller(text_widgets, spacing=28, line_separator=True)

    def init_window(self):
        """Initialize the raylib window."""
        gui_app.init_window("Screen Tearing Stress Test")
        if self.text_scroller is None:
            self._setup_text_scroller()

    def get_tearing_color(self, x: float, y: float, time: float) -> rl.Color:
        """Generate colors that change rapidly to exacerbate tearing."""
        # Create high-frequency color changes
        r = int(128 + 127 * math.sin(time * self.color_cycle_speed + x * 0.01))
        g = int(128 + 127 * math.sin(time * self.color_cycle_speed * 1.1 + y * 0.01))
        b = int(128 + 127 * math.sin(time * self.color_cycle_speed * 1.2 + (x + y) * 0.005))

        # Clamp values
        r = max(0, min(255, r))
        g = max(0, min(255, g))
        b = max(0, min(255, b))

        return rl.Color(r, g, b, 255)

    def draw_horizontal_lines(self, time: float):
        """Draw rapidly moving horizontal lines."""
        for i in range(0, gui_app.height, self.line_thickness * 2):
            y = (i + int(time * self.speed_multiplier * 100)) % gui_app.height
            color = self.get_tearing_color(0, y, time)
            rl.draw_line(0, y, gui_app.width, y, color)

    def draw_vertical_lines(self, time: float):
        """Draw rapidly moving vertical lines."""
        for i in range(0, gui_app.width, self.line_thickness * 2):
            x = (i + int(time * self.speed_multiplier * 100)) % gui_app.width
            color = self.get_tearing_color(x, 0, time)
            rl.draw_line(x, 0, x, gui_app.height, color)

    def draw_diagonal_lines(self, time: float):
        """Draw diagonal lines moving across the screen."""
        # Simple approach: draw diagonal lines from left to right
        spacing = 40
        offset = int(time * self.speed_multiplier * 100) % (gui_app.width + gui_app.height)

        for i in range(0, gui_app.width + gui_app.height, spacing):
            # Calculate diagonal line coordinates
            x1 = i + offset - gui_app.height
            y1 = 0
            x2 = i + offset
            y2 = gui_app.height

            # Only draw if the line intersects the screen
            if x1 < gui_app.width and x2 > 0:
                # Clamp coordinates to screen bounds
                x1 = max(0, min(gui_app.width - 1, x1))
                x2 = max(0, min(gui_app.width - 1, x2))

                color = self.get_tearing_color(x1, y1, time)
                rl.draw_line(x1, y1, x2, y2, color)

        # Also draw some simple diagonal lines for testing
        for i in range(0, gui_app.width, 100):
            x1 = i + int(time * self.speed_multiplier * 50) % gui_app.width
            y1 = 0
            x2 = x1 + 200
            y2 = gui_app.height

            if x2 < gui_app.width:
                color = self.get_tearing_color(x1, y1, time)
                rl.draw_line(x1, y1, x2, y2, color)



    def draw_rotating_squares(self, time: float):
        """Draw rotating squares."""
        center_x = gui_app.width // 2
        center_y = gui_app.height // 2
        rotation = time * self.speed_multiplier * 2

        for i in range(8):
            # Much larger squares - start at 100, increase by 50 each time
            size = 100 + i * 50
            angle = rotation + i * 0.5

            # Calculate rotated square corners
            cos_a = math.cos(angle)
            sin_a = math.sin(angle)

            half_size = size // 2
            corners = [
                (center_x + int(-half_size * cos_a - (-half_size) * sin_a),
                 center_y + int(-half_size * sin_a + (-half_size) * cos_a)),
                (center_x + int(half_size * cos_a - (-half_size) * sin_a),
                 center_y + int(half_size * sin_a + (-half_size) * cos_a)),
                (center_x + int(half_size * cos_a - half_size * sin_a),
                 center_y + int(half_size * sin_a + half_size * cos_a)),
                (center_x + int(-half_size * cos_a - half_size * sin_a),
                 center_y + int(-half_size * sin_a + half_size * cos_a))
            ]

            color = self.get_tearing_color(center_x, center_y, time + i)
            rl.draw_line_strip(corners, len(corners), color)

    def draw_pulsing_circles(self, time: float):
        """Draw pulsing circles."""
        for i in range(20):
            x = (i * 100 + int(time * self.speed_multiplier * 20)) % gui_app.width
            y = (i * 50 + int(time * self.speed_multiplier * 15)) % gui_app.height
            radius = int(20 + 15 * math.sin(time * self.speed_multiplier * 3 + i))

            color = self.get_tearing_color(x, y, time + i)
            rl.draw_circle(x, y, radius, color)

    def draw_text_scrolling(self, time: float):
        """Draw text-heavy vertical scrolling pattern using firehose widget."""
        if self.text_scroller is None:
            return

        # Create a full-screen rectangle for the scroller
        scroller_rect = rl.Rectangle(0, 0, gui_app.width, gui_app.height)

        # Set the scroller position and render it
        self.text_scroller.set_position(0, 0)
        self.text_scroller.set_parent_rect(scroller_rect)
        self.text_scroller.render()

    def draw_test_pattern(self, time: float):
        """Draw the current test pattern."""
        if self.test_mode == 0:
            self.draw_horizontal_lines(time)
        elif self.test_mode == 1:
            self.draw_text_scrolling(time)
        elif self.test_mode == 2:
            self.draw_vertical_lines(time)
        elif self.test_mode == 3:
            self.draw_diagonal_lines(time)
        elif self.test_mode == 4:
            self.draw_rotating_squares(time)
        elif self.test_mode == 5:
            self.draw_pulsing_circles(time)

    def draw_ui_overlay(self):
        """Draw UI overlay with controls and information."""

        rl.draw_rectangle(10, 10, 400, 70, rl.Color(0, 0, 0, 128))

        font = gui_app.font(FontWeight.NORMAL)

        rl.draw_text_ex(font, "Screen Tearing Stress Test", rl.Vector2(20, 20), 20, 0, rl.WHITE)
        rl.draw_text_ex(font, f"Pattern: {self.patterns[self.test_mode]}", rl.Vector2(20, 50), 16, 0, rl.WHITE)

    def update_pattern_cycle(self, current_time: float):
        """Automatically cycle through test patterns every 5 seconds."""
        if current_time - self.last_pattern_change >= self.pattern_duration:
            self.test_mode = (self.test_mode + 1) % len(self.patterns)
            self.last_pattern_change = current_time

    def run(self):
        """Main application loop."""
        self.init_window()

        try:
            for should_render in gui_app.render():
                if not should_render:
                    continue

                # Update animation time
                self.animation_time = time.monotonic() * 10  # Speed up animation
                current_time = time.monotonic()

                # Update pattern cycling
                self.update_pattern_cycle(current_time)

                # Draw the stress test pattern
                self.draw_test_pattern(self.animation_time)

                # Draw UI overlay
                self.draw_ui_overlay()

                # End drawing
                rl.end_drawing()

        except KeyboardInterrupt:
            pass
        finally:
            gui_app.close()


def main():
    """Entry point for the stress test application."""
    config_realtime_process([1, 2], 1)
    print("Starting Screen Tearing Stress Test...")
    print("This application is designed to exacerbate screen tearing.")
    print("Use the controls to adjust patterns and intensity.")

    stress_test = ScreenTearingStressTest()
    stress_test.run()


if __name__ == "__main__":
    main()
