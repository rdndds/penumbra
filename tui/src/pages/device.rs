/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use std::sync::Arc;
use std::time::{Duration, Instant};

use hex::encode;
use penumbra::core::devinfo::{DevInfoData, DeviceInfo};
use penumbra::core::seccfg::LockFlag;
use penumbra::{Device, DeviceBuilder, MTKPort, find_mtk_port};
use ratatui::Frame;
use ratatui::crossterm::event::{KeyCode, KeyEvent};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use strum::IntoEnumIterator;
use strum_macros::{AsRefStr, EnumIter};
use tokio::sync::{Mutex, mpsc};
use tokio::time::sleep;

use crate::app::{AppCtx, AppPage};
use crate::components::selectable_list::{
    ListItemEntry,
    ListItemEntryBuilder,
    SelectableList,
    SelectableListBuilder,
};
use crate::pages::Page;

type DeviceResult = Result<(Arc<Mutex<Device>>, DeviceInfo), String>;

enum AppEvent {
    DevicePortFound,
    DeviceInitResult(DeviceResult),
    SetLockStateResult(Result<(), String>, String),
}

#[derive(Clone, PartialEq, Default)]
enum DeviceStatus {
    #[default]
    WaitingForDevice,
    Initializing,
    DAReady,
    Error(String),
}

#[derive(EnumIter, AsRefStr, Debug, Clone, Copy)]
enum DeviceAction {
    #[strum(serialize = "Unlock Bootloader")]
    UnlockBootloader,
    #[strum(serialize = "Lock Bootloader")]
    LockBootloader,
    #[strum(serialize = "Back to Menu")]
    BackToMenu,
}

pub struct DevicePage {
    menu: SelectableList,
    actions: Vec<DeviceAction>,
    device: Option<Arc<Mutex<Device>>>,
    status: DeviceStatus,
    status_message: Option<(String, Style)>,
    last_poll: Instant,
    device_info: Option<DeviceInfo>,
    // This is used only in render, since render is not async, and we can't await inside it.
    devinfo_data: Option<DevInfoData>,
    is_polling: bool,
    event_tx: mpsc::Sender<AppEvent>,
    event_rx: mpsc::Receiver<AppEvent>,
}

impl DevicePage {
    pub fn new() -> Self {
        let actions: Vec<DeviceAction> = DeviceAction::iter().collect();
        let menu_items: Vec<ListItemEntry> = actions
            .iter()
            .map(|action| {
                let icon = match action {
                    DeviceAction::UnlockBootloader => '🔓',
                    DeviceAction::LockBootloader => '🔒',
                    DeviceAction::BackToMenu => '❌',
                };
                let label = action.as_ref().to_string();

                ListItemEntryBuilder::new(label).icon(icon).build().unwrap()
            })
            .collect();
        let menu: SelectableList = SelectableListBuilder::default()
            .items(menu_items)
            .highlight_symbol(">>".to_string())
            .build()
            .unwrap();

        let (event_tx, event_rx) = mpsc::channel(10);

        Self {
            menu,
            actions,
            device: None,
            status: DeviceStatus::default(),
            status_message: None,
            last_poll: Instant::now(),
            device_info: None,
            devinfo_data: None,
            is_polling: false,
            event_tx,
            event_rx,
        }
    }

    fn poll_device(&mut self, ctx: &mut AppCtx) {
        if self.is_polling || self.last_poll.elapsed() < Duration::from_millis(500) {
            return;
        }

        self.last_poll = Instant::now();
        self.is_polling = true;

        let da_data: Option<Vec<u8>> = ctx.loader().map(|l| l.file().da_raw_data.clone());
        let tx = self.event_tx.clone();

        tokio::spawn(async move {
            let port: Box<dyn MTKPort>;
            loop {
                match find_mtk_port().await {
                    Some(p) => {
                        port = p;
                        break;
                    }
                    None => {
                        sleep(Duration::from_millis(500)).await;
                    }
                }
            }

            if tx.send(AppEvent::DevicePortFound).await.is_err() {
                return;
            }

            let result = Self::init_device(port, da_data).await;
            let _ = tx.send(AppEvent::DeviceInitResult(result)).await;
        });
    }

    async fn init_device(port: Box<dyn MTKPort>, da_data: Option<Vec<u8>>) -> DeviceResult {
        let da_data = da_data.ok_or_else(|| "No DA loader in context".to_string())?;

        let mut dev = DeviceBuilder::default()
            .with_da_data(da_data)
            .with_mtk_port(port)
            .build()
            .map_err(|e| format!("Device build failed: {e}"))?;

        dev.init().await.map_err(|e| format!("Device init failed: {e}"))?;
        dev.enter_da_mode().await.map_err(|e| format!("Failed to enter DA mode: {e}"))?;

        let dev_info = dev.dev_info.clone();
        Ok((Arc::new(Mutex::new(dev)), dev_info))
    }

    fn set_device_lock_state(&mut self, flag: LockFlag, label: String) {
        if self.device.is_none() {
            self.status = DeviceStatus::Error("No device connected".to_string());
            return;
        }

        let tx = self.event_tx.clone();
        let dev_arc = self.device.clone().unwrap();

        tokio::spawn(async move {
            let result = async {
                let mut dev = dev_arc.lock().await;
                dev.set_seccfg_lock_state(flag)
                    .await
                    .map(|_| ())
                    .ok_or_else(|| "Failed to change lock state".to_string())
            }
            .await;
            let _ = tx.send(AppEvent::SetLockStateResult(result, label)).await;
        });
    }
}

#[async_trait::async_trait]
impl Page for DevicePage {
    async fn handle_input(&mut self, ctx: &mut AppCtx, key: KeyEvent) {
        match key.code {
            KeyCode::Up => self.menu.previous(),
            KeyCode::Down => self.menu.next(),
            KeyCode::Enter => {
                let action = self.actions[self.menu.selected_index().unwrap_or(2)];
                match action {
                    DeviceAction::UnlockBootloader | DeviceAction::LockBootloader => {
                        let (label, flag) = match action {
                            DeviceAction::UnlockBootloader => ("Unlock", LockFlag::Unlock),
                            DeviceAction::LockBootloader => ("Lock", LockFlag::Lock),
                            _ => unreachable!(),
                        };
                        self.set_device_lock_state(flag, label.to_string());
                    }
                    DeviceAction::BackToMenu => ctx.change_page(AppPage::Welcome),
                }
            }
            _ => {}
        }
    }

    fn render(&mut self, frame: &mut Frame<'_>, _ctx: &mut AppCtx) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Length(8), Constraint::Min(5)])
            .split(frame.area());

        let (status_line, style) = match &self.status {
            DeviceStatus::WaitingForDevice => (
                "Waiting for device...".to_string(),
                Style::default().fg(Color::Yellow).bg(Color::Black),
            ),
            DeviceStatus::Initializing => (
                "Initializing device...".to_string(),
                Style::default().fg(Color::Cyan).bg(Color::Black),
            ),
            DeviceStatus::DAReady => {
                ("DA mode active.".to_string(), Style::default().fg(Color::Green).bg(Color::Black))
            }
            DeviceStatus::Error(msg) => {
                (format!("Error: {msg}"), Style::default().fg(Color::Red).bg(Color::Black))
            }
        };

        let mut status_lines = vec![status_line];
        let paragraph_style = if let Some((msg, msg_style)) = &self.status_message {
            status_lines.push(msg.clone());
            msg_style.clone()
        } else {
            style
        };

        frame.render_widget(
            Paragraph::new(status_lines.join("\n"))
                .style(paragraph_style)
                .block(Block::default().borders(Borders::ALL)),
            layout[0],
        );

        let info_lines = match &self.devinfo_data {
            Some(info) => {
                vec![
                    format!("SoC ID: {}", encode(&info.soc_id)),
                    format!("MeID: {}", encode(&info.meid)),
                    format!("SBC: {}", (info.target_config & 0x1 != 0)),
                    format!("SLA: {}", (info.target_config & 0x2 != 0)),
                    format!("DAA: {}", (info.target_config & 0x4 != 0)),
                ]
            }
            None => vec!["No device info available".to_string()],
        };

        frame.render_widget(
            Paragraph::new(info_lines.join("\n"))
                .block(Block::default().title("Device Info").borders(Borders::ALL))
                .style(Style::default().fg(Color::Cyan)),
            layout[1],
        );

        self.menu.render(layout[2], frame, "Actions");
    }

    async fn on_enter(&mut self, _ctx: &mut AppCtx) {
        self.menu.state.select(Some(0));
        self.status = DeviceStatus::WaitingForDevice;
        self.last_poll = Instant::now();
        self.device = None;
        self.device_info = None;
        self.is_polling = false;
        while self.event_rx.try_recv().is_ok() {}
    }

    async fn on_exit(&mut self, _ctx: &mut AppCtx) {}

    async fn update(&mut self, ctx: &mut AppCtx) {
        if let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::DevicePortFound => {
                    self.status = DeviceStatus::Initializing;
                }
                AppEvent::DeviceInitResult(Ok((dev, dev_info))) => {
                    self.status = DeviceStatus::DAReady;
                    self.device_info = Some(dev_info);
                    self.devinfo_data = Some(self.device_info.as_ref().unwrap().get_data().await);
                    self.device = Some(dev);
                    self.is_polling = false;
                }
                AppEvent::DeviceInitResult(Err(_)) => {
                    self.status = DeviceStatus::WaitingForDevice;
                    self.is_polling = false;
                }
                AppEvent::SetLockStateResult(Ok(_), label) => {
                    self.status_message = Some((
                        format!("{label} done."),
                        Style::default().fg(Color::Green).bg(Color::Black),
                    ));
                }
                AppEvent::SetLockStateResult(Err(e), label) => {
                    self.status = DeviceStatus::Error(format!("{label} failed: {e}"));
                }
            }
        }

        if self.status == DeviceStatus::WaitingForDevice {
            self.poll_device(ctx);
        }

        if self.last_poll.elapsed() > Duration::from_secs(5) {
            self.devinfo_data = match &self.device_info {
                Some(info) => Some(info.get_data().await),
                None => None,
            }
        }
    }
}
