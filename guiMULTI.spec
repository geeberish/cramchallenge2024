# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['guiMULTI.py'],
    pathex=[],
    binaries=[
    ],
    datas=[
        ('get_nvd_data.py', '.'),  # Include get_nvd_data.py
        ('average_nvd_data.py', '.'), 
        ('analysisorchestration.py', '.'), 
        ('LLamaPPP.py', '.'), 
        ('APT.py', '.'), 
        ('set_max_node_criticalites.py', '.'), 
        ('calculate_modified_scores.py', '.'), 
        ('sue_data_2.0', 'sue_data_2.0'),  # Include sue_data folder
        ('sue_data_2.0/json_data', 'sue_data_2.0/json_data'),  # Include json_data folder within sue_data
        ('sue_data_2.0/json_data/apt_group.json', 'sue_data/json_data'),  # Include apt_group.json within json_data
        ('sue_data_2.0/txt_data', 'sue_data_2.0/txt_data'),  # Include txt_data folder within sue_data
        ('frameworks', 'frameworks'),  # Include frameworks folder
        ('submissions', 'submissions'),  # Include submissions folder
    ],
    hiddenimports=[ 
        'PySide6.QtWidgets', 
        'PySide6.QtCore', 
        'PySide6.QtGui', 
        'matplotlib', 
        'nvdlib',  
        'nvdlib.classes',  
        'nvdlib.constants', 
        'nvdlib.exceptions',
        'nvdlib.query',
        'nvdlib.utils',
        'requests',  
        'boto3',
        'tqdm',
        'subprocess', 
        'hashlib', 
        'csv', 
        'sys', 
        'os', 
        'shutil', 
        'datetime', 
        'matplotlib.backends.backend_qt5agg',
        'groq', 
        'pyinstaller',
        'threading',
        'platform'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='ACRES',
    icon='files\\logo.ico',
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
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='guiMULTI',
)
