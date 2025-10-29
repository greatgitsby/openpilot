#!/usr/bin/env python3
"""
Screen Tearing Stress Test Application

This application is designed to exacerbate screen tearing by creating various
visual patterns that are particularly susceptible to tearing artifacts.
It uses the lib/application as the base for window creation and rendering.
"""

import math
import time
import random
import pyray as rl
from openpilot.system.ui.lib.application import FontWeight, GuiApplication


class ScreenTearingStressTest:
    """Stress test application designed to exacerbate screen tearing."""

    def __init__(self):
        # Create application with standard openpilot dimensions
        self.app = GuiApplication(2160, 1080)

        # Test parameters
        self.time_offset = 0.0
        self.test_mode = 0  # 0: horizontal lines, 1: vertical lines, 2: diagonal, 3: checkerboard, 4: random
        self.speed_multiplier = 1.0
        self.line_thickness = 2
        self.color_cycle_speed = 1.0
        self.enable_vsync = False
        self.show_fps = True
        self.show_instructions = True

        # Animation state
        self.animation_time = 0.0
        self.color_offset = 0.0
        self.last_pattern_change = 0.0
        self.pattern_duration = 5.0  # 5 seconds per pattern

        # Test patterns data
        self.patterns = [
            "Horizontal Lines",
            "Vertical Lines",
            "Diagonal Lines",
            "Checkerboard",
            "Random Pixels",
            "Sine Wave",
            "Rotating Squares",
            "Pulsing Circles"
        ]

    def init_window(self):
        """Initialize the raylib window."""
        self.app.init_window("Screen Tearing Stress Test")

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
        for i in range(0, self.app.height, self.line_thickness * 2):
            y = (i + int(time * self.speed_multiplier * 100)) % self.app.height
            color = self.get_tearing_color(0, y, time)
            rl.draw_line(0, y, self.app.width, y, color)

    def draw_vertical_lines(self, time: float):
        """Draw rapidly moving vertical lines."""
        for i in range(0, self.app.width, self.line_thickness * 2):
            x = (i + int(time * self.speed_multiplier * 100)) % self.app.width
            color = self.get_tearing_color(x, 0, time)
            rl.draw_line(x, 0, x, self.app.height, color)

    def draw_diagonal_lines(self, time: float):
        """Draw diagonal lines moving across the screen."""
        # Simple approach: draw diagonal lines from left to right
        spacing = 40
        offset = int(time * self.speed_multiplier * 100) % (self.app.width + self.app.height)

        for i in range(0, self.app.width + self.app.height, spacing):
            # Calculate diagonal line coordinates
            x1 = i + offset - self.app.height
            y1 = 0
            x2 = i + offset
            y2 = self.app.height

            # Only draw if the line intersects the screen
            if x1 < self.app.width and x2 > 0:
                # Clamp coordinates to screen bounds
                x1 = max(0, min(self.app.width - 1, x1))
                x2 = max(0, min(self.app.width - 1, x2))

                color = self.get_tearing_color(x1, y1, time)
                rl.draw_line(x1, y1, x2, y2, color)

        # Also draw some simple diagonal lines for testing
        for i in range(0, self.app.width, 100):
            x1 = i + int(time * self.speed_multiplier * 50) % self.app.width
            y1 = 0
            x2 = x1 + 200
            y2 = self.app.height

            if x2 < self.app.width:
                color = self.get_tearing_color(x1, y1, time)
                rl.draw_line(x1, y1, x2, y2, color)

    def draw_checkerboard(self, time: float):
        """Draw a moving checkerboard pattern."""
        square_size = 20
        offset_x = int(time * self.speed_multiplier * 30) % (square_size * 2)
        offset_y = int(time * self.speed_multiplier * 30) % (square_size * 2)

        for x in range(0, self.app.width + square_size, square_size):
            for y in range(0, self.app.height + square_size, square_size):
                check_x = (x + offset_x) // square_size
                check_y = (y + offset_y) // square_size

                if (check_x + check_y) % 2 == 0:
                    color = self.get_tearing_color(x, y, time)
                    rl.draw_rectangle(x, y, square_size, square_size, color)

    def draw_random_pixels(self, time: float):
        """Draw random pixels that change rapidly."""
        random.seed(int(time * 100))
        for _ in range(10000):  # High pixel count for stress
            x = random.randint(0, self.app.width - 1)
            y = random.randint(0, self.app.height - 1)
            color = self.get_tearing_color(x, y, time)
            rl.draw_pixel(x, y, color)

    def draw_sine_wave(self, time: float):
        """Draw animated sine waves."""
        for x in range(0, self.app.width, 2):
            # Multiple sine waves with different frequencies
            y1 = int(self.app.height // 2 + 100 * math.sin(x * 0.01 + time * self.speed_multiplier))
            y2 = int(self.app.height // 2 + 80 * math.sin(x * 0.015 + time * self.speed_multiplier * 1.2))
            y3 = int(self.app.height // 2 + 60 * math.sin(x * 0.02 + time * self.speed_multiplier * 0.8))

            color1 = self.get_tearing_color(x, y1, time)
            color2 = self.get_tearing_color(x, y2, time)
            color3 = self.get_tearing_color(x, y3, time)

            rl.draw_pixel(x, y1, color1)
            rl.draw_pixel(x, y2, color2)
            rl.draw_pixel(x, y3, color3)

    def draw_rotating_squares(self, time: float):
        """Draw rotating squares."""
        center_x = self.app.width // 2
        center_y = self.app.height // 2
        rotation = time * self.speed_multiplier * 2

        for i in range(10):
            size = 50 + i * 20
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
            x = (i * 100 + int(time * self.speed_multiplier * 20)) % self.app.width
            y = (i * 50 + int(time * self.speed_multiplier * 15)) % self.app.height
            radius = int(20 + 15 * math.sin(time * self.speed_multiplier * 3 + i))

            color = self.get_tearing_color(x, y, time + i)
            rl.draw_circle(x, y, radius, color)

    def draw_test_pattern(self, time: float):
        """Draw the current test pattern."""
        if self.test_mode == 0:
            self.draw_horizontal_lines(time)
        elif self.test_mode == 1:
            self.draw_vertical_lines(time)
        elif self.test_mode == 2:
            self.draw_diagonal_lines(time)
        elif self.test_mode == 3:
            self.draw_checkerboard(time)
        elif self.test_mode == 4:
            self.draw_random_pixels(time)
        elif self.test_mode == 5:
            self.draw_sine_wave(time)
        elif self.test_mode == 6:
            self.draw_rotating_squares(time)
        elif self.test_mode == 7:
            self.draw_pulsing_circles(time)

    def draw_ui_overlay(self):
        """Draw UI overlay with controls and information."""
        if not self.show_instructions:
            return

        # Semi-transparent background
        rl.draw_rectangle(10, 10, 400, 70, rl.Color(0, 0, 0, 128))

        # Get font for text rendering
        font = self.app.font(FontWeight.NORMAL)

        # Instructions
        y_offset = 20
        rl.draw_text_ex(font, "Screen Tearing Stress Test", rl.Vector2(20, y_offset), 20, 0, rl.WHITE)
        y_offset += 30

        rl.draw_text_ex(font, f"Pattern: {self.patterns[self.test_mode]}", rl.Vector2(20, y_offset), 16, 0, rl.WHITE)

    def update_pattern_cycle(self, current_time: float):
        """Automatically cycle through test patterns every 5 seconds."""
        if current_time - self.last_pattern_change >= self.pattern_duration:
            self.test_mode = (self.test_mode + 1) % len(self.patterns)
            self.last_pattern_change = current_time


    def run(self):
        """Main application loop."""
        self.init_window()

        try:
            for should_render in self.app.render():
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
            self.app.close()


def main():
    """Entry point for the stress test application."""
    print("Starting Screen Tearing Stress Test...")
    print("This application is designed to exacerbate screen tearing.")
    print("Use the controls to adjust patterns and intensity.")

    stress_test = ScreenTearingStressTest()
    stress_test.run()


if __name__ == "__main__":
    main()
