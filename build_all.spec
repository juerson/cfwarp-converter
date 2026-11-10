# -*- mode: python ; coding: utf-8 -*-

# 双 exe 打包主配置（main.exe + register.exe 共享一份 _internal）
# 打包命令：pyinstaller build_all.spec --noconfirm

main_a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

register_a = Analysis(
    ['register.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

main_pyz = PYZ(main_a.pure)
register_pyz = PYZ(register_a.pure)

main_exe = EXE(
    main_pyz,
    main_a.scripts,
    [],
    exclude_binaries=True,
    name='main',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

register_exe = EXE(
    register_pyz,
    register_a.scripts,
    [],
    exclude_binaries=True,
    name='register',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    main_exe,
    register_exe,
    main_a.binaries,
    main_a.datas,
    register_a.binaries,
    register_a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='cfwarp-converter',
)