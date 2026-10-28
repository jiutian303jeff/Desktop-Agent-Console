# Desktop Agent Console

A small Windows desktop app that lets an AI help with tasks on your computer.

It tries to work in the background using Python scripts and PowerShell commands first. When a task needs screen access, it can ask for permission to take screenshots, click, and type.

The app is written in a single Python file and can be packaged into a single `.exe`.

## Features

- Simple chat interface with always-on-top and collapse options
- Configurable API Key, Base URL, and Model Name
- Saved settings that load automatically on startup
- Background Python and PowerShell execution
- Optional screenshot, mouse, and keyboard tools
- Manual approval for background code by default
- Global **F12** emergency stop
- Chinese and other Unicode text input

The default model name is `gpt-6-astra`. You can change it in the app.

## Requirements

- Windows 10 or 11
- Python 3.11 or 3.12 for running the source or building the app
- An API service that supports the OpenAI Responses API and function calling
- A model with image input support if you want to use screenshots

Not every model or OpenAI-compatible service supports the same features and request parameters.

## Installation

Clone or download this repository, then open a terminal in the project folder.

Create a virtual environment:

```powershell
python -m venv .venv
```

Install the dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install openai customtkinter pillow mss pyautogui pyinstaller
```

Run the app:

```powershell
.\.venv\Scripts\python.exe agent_app.py
```

## Getting Started

1. Enter your API Key.
2. Enter your Base URL, such as `https://api.openai.com/v1`.
3. Enter the model name available through your API service.
4. Click the save configuration button.
5. Describe your task and send it.

The current interface uses Chinese labels.

Background code requires approval unless you enable automatic approval for the task. Screen access is disabled by default. To use it, enable visual fallback and approve the request when prompted.

Press **F12** to stop the current controlled task.

A simple first task:

> Create a file named hello.txt in the working directory, write "Hello, Agent!" into it, and read it back to check the result. Use Python only. Do not take screenshots or use the mouse.

## Build a Single EXE

Run this command on Windows:

```powershell
.\.venv\Scripts\python.exe -m PyInstaller --noconfirm --clean --onefile --windowed --name AgentConsole --collect-all customtkinter --collect-submodules openai --hidden-import mss.windows --hidden-import pyautogui._pyautogui_win --collect-data certifi agent_app.py
```

The executable will be created at:

```text
dist\AgentConsole.exe
```

The target computer does not need a separate Python installation for the bundled Python tool. External apps, such as Blender or KiCad, still need to be installed separately.

## Settings and Working Files

Settings are stored at:

```text
%LOCALAPPDATA%\DesktopAgentConsole\config.json
```

The default working directory is:

```text
%LOCALAPPDATA%\DesktopAgentConsole\workspace\
```

The API Key is encrypted using Windows DPAPI for the current Windows user. The Base URL and model name are stored as plain text.

Do not commit API keys, personal configuration files, or private task output to GitHub.

## Safety and Privacy

**This app is not a sandbox.** Generated Python and PowerShell code runs with your Windows account's permissions. Review code before approving it, and only enable automatic approval for tasks you trust.

Your prompts, tool results, and approved screenshots are sent to the configured API service. Close sensitive windows before allowing screenshots.

F12 stops the controlled task processes, but it cannot undo changes that have already happened. It may not stop work handed off to an existing external app or a remote service.

Use a normal Windows account rather than running the app as administrator whenever possible.

## Current Limitations

- Visual tools support the primary monitor only.
- Screenshots show visible content, not an entire document.
- Visual mode moves the real mouse and types into the focused window.
- Arbitrary background code is not technically prevented from accessing desktop APIs; approval remains important.
- Dynamic Python scripts can only import modules available in the packaged app.
- There is no built-in Google Docs API connection.
- Some apps, protected windows, and API services may need additional setup.

For important work, keep backups and check the result before relying on it.
