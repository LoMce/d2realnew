# Responsible ImGui

A sophisticated ImGui-based application framework with advanced memory manipulation capabilities and authentication system.

## 🚀 Features

### Core Functionality
- **ImGui Integration**: Modern, responsive UI built with Dear ImGui
- **Kernel Driver Communication**: Direct kernel-level memory operations
- **Authentication System**: Secure KeyAuth integration for user management
- **Multi-Platform Support**: x86 and x64 architecture compatibility

### Advanced Capabilities
- **Memory Management**: Process memory reading/writing with kernel driver
- **AOB (Array of Bytes) Scanning**: Pattern matching across process memory
- **Codecave Injection**: Dynamic code injection with shellcode execution
- **Hotkey System**: Configurable key bindings with persistence
- **Teleport Manager**: Coordinate-based teleportation system
- **Theme System**: Customizable UI themes (Catppuccin included)

### Game Features
- **Player Management**: Real-time player coordinate tracking
- **View Angle Control**: Camera manipulation capabilities
- **Flight System**: Advanced 3D movement with boost mechanics
- **Damage Modifications**: Configurable damage multipliers
- **Utility Features**: FOV adjustment, infinite resources, and more

## 📁 Project Structure

```
ResponsibleImGui/
├── Source/
│   ├── ImGui Standalone/           # Main application
│   │   ├── Drawing.cpp            # Core UI rendering
│   │   ├── Features.h             # Game feature definitions
│   │   ├── KeyAuthManager.*       # Authentication system
│   │   ├── TPManager.*            # Teleport management
│   │   ├── UI.*                   # UI framework
│   │   └── themes.h               # UI theming
│   └── IUIC_ImGui.sln            # Visual Studio solution
├── DX11-BaseHook/                 # DirectX 11 hook implementation
├── KeyAuth-CPP-Example-main/      # Authentication examples
└── minhook/                       # MinHook library files
```

## 🛠️ Requirements

### Development Environment
- **Visual Studio 2019/2022** with C++20 support
- **DirectX SDK** (DXSDK_DIR environment variable required)
- **Windows 10/11** (Administrator privileges required)

### Dependencies
- **DirectX 11** for rendering
- **MinHook** for API hooking
- **KeyAuth** for authentication
- **nlohmann/json** for configuration management

## 🚀 Getting Started

### Environment Setup
1. **Install DirectX SDK**
   - Download from [Microsoft DirectX SDK](https://www.microsoft.com/en-us/download/details.aspx?id=6812)
   - Ensure `DXSDK_DIR` environment variable is set

2. **Verify Environment Variables**
   ```
   Settings → System → About → Advanced System Settings → Environment Variables
   ```

### Building the Project
1. Open `IUIC_ImGui.sln` in Visual Studio
2. Select your target configuration:
   - **Debug/Release**
   - **x86/x64**
3. Build the solution (Ctrl+Shift+B)

### Configuration Options
- **EXE Mode**: Standalone executable application
- **DLL Mode**: Injectable library for external processes

## 🎮 Usage

### Initial Setup
1. Run the application as Administrator
2. Complete authentication through KeyAuth
3. Configure hotkeys and preferences

### Basic Operations
- **Authentication**: Secure login system with license validation
- **Feature Toggle**: Enable/disable individual game features
- **Hotkey Management**: Customize key bindings for all features
- **Teleport System**: Save and load coordinate-based teleports
- **Configuration**: Save/load complete feature sets

### Advanced Features
- **Memory Scanning**: Real-time AOB pattern detection
- **Code Injection**: Dynamic shellcode execution
- **Process Hooking**: Kernel-level memory manipulation
- **Multi-Threading**: Concurrent feature processing

## 🔧 Configuration

### Hotkeys Configuration
```cpp
// Default hotkeys (customizable)
FlyToggle: H
FlyBoost: G
AbilityCharge: VK_5
```

### File Locations
- **Hotkeys**: `%USERPROFILE%\Documents\Hatemob\Hotkeys\hotkeys.json`
- **Configs**: Application directory
- **Teleports**: Managed by TPManager

## 🎨 Theming

The application supports custom themes with the Catppuccin theme included by default. Themes can be modified in `themes.h`.

## ⚡ Performance

- **Optimized Rendering**: Stable 185 FPS limit with efficient frame pacing
- **Memory Efficient**: Minimal memory footprint with smart allocation
- **Low Latency**: Sub-millisecond response times for critical operations

## 🔐 Security Features

- **Kernel Driver**: Secure memory operations
- **Authentication**: License-based access control
- **Process Validation**: Target process verification
- **Memory Protection**: Safe injection techniques

## 🐛 Troubleshooting

### Common Issues
1. **Driver Handle Failed**
   - Ensure administrator privileges
   - Verify kernel driver is loaded

2. **DirectX Linking Errors**
   - Check DXSDK_DIR environment variable
   - Reinstall DirectX SDK

3. **Authentication Failures**
   - Verify internet connection
   - Check license validity

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is for educational and research purposes only. Users are responsible for complying with all applicable laws and terms of service when using this software.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

chatgpt generated all this 😹
