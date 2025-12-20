/*
    SPDX-License-Identifier:  AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::time::{Duration, Instant};

use rand::Rng;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};

// TODO: Consider adding more stars for more whimsy vibes
const STAR_CHARS: [char; 4] = ['✦', '✧', '·', ' '];

#[derive(Clone)]
struct Star {
    x: u16,
    y: u16,
    char_idx: usize,
    next_twinkle: Instant,
}

pub struct Stars {
    stars: Vec<Star>,
    last_area: Rect,
    density: f32,
}

impl Default for Stars {
    fn default() -> Self {
        Self::new(0.8)
    }
}

impl Stars {
    pub fn new(density: f32) -> Self {
        Self { stars: Vec::new(), last_area: Rect::default(), density }
    }

    /// Stars are more sparse, fewer stars
    pub fn sparse() -> Self {
        Self::new(0.4)
    }

    /// Lots of stars
    pub fn dense() -> Self {
        Self::new(2.0)
    }

    /// Call this every frame to update star twinkle states
    pub fn tick(&mut self) {
        let now = Instant::now();
        let mut rng = rand::rng();

        for star in &mut self.stars {
            if now >= star.next_twinkle {
                if rng.random_bool(0.7) {
                    star.char_idx = (star.char_idx + 1) % STAR_CHARS.len();
                } else {
                    star.char_idx = rng.random_range(0..STAR_CHARS.len());
                }

                let delay = rng.random_range(150..400);
                star.next_twinkle = now + Duration::from_millis(delay);
            }
        }
    }

    fn regenerate(&mut self, area: Rect) {
        let mut rng = rand::rng();
        self.stars.clear();

        let total_cells = area.width as f32 * area.height as f32;
        let num_stars = ((total_cells / 100.0) * self.density) as usize;

        let now = Instant::now();

        for _ in 0..num_stars {
            let x = rng.random_range(area.x..area.x + area.width);
            let y = rng.random_range(area.y..area.y + area.height);
            let char_idx = rng.random_range(0..STAR_CHARS.len());
            let delay = rng.random_range(0..500);

            self.stars.push(Star {
                x,
                y,
                char_idx,
                next_twinkle: now + Duration::from_millis(delay),
            });
        }

        self.last_area = area;
    }

    /// Render stars in the given area
    pub fn render(&mut self, area: Rect, buf: &mut Buffer) {
        if area != self.last_area {
            self.regenerate(area);
        }

        let style = Style::default().fg(Color::DarkGray);

        for star in &self.stars {
            if star.x >= area.x
                && star.x < area.x + area.width
                && star.y >= area.y
                && star.y < area.y + area.height
            {
                let ch = STAR_CHARS[star.char_idx];
                if ch != ' '
                    && let Some(cell) = buf.cell_mut((star.x, star.y))
                {
                    cell.set_char(ch).set_style(style);
                }
            }
        }
    }

    /// Render stars only in top and bottom bands
    pub fn render_bands(&mut self, area: Rect, buf: &mut Buffer, top_rows: u16, bottom_rows: u16) {
        if area != self.last_area {
            self.regenerate(area);
        }

        let style = Style::default().fg(Color::DarkGray);

        for star in &self.stars {
            let in_top = star.y >= area.y && star.y < area.y + top_rows;
            let in_bottom = star.y >= area.y + area.height.saturating_sub(bottom_rows)
                && star.y < area.y + area.height;

            if (in_top || in_bottom) && star.x >= area.x && star.x < area.x + area.width {
                let ch = STAR_CHARS[star.char_idx];
                if ch != ' '
                    && let Some(cell) = buf.cell_mut((star.x, star.y))
                {
                    cell.set_char(ch).set_style(style);
                }
            }
        }
    }
}
