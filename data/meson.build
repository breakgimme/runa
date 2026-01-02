install_data(
  'me.breakgim.runa.desktop.in',
  rename: 'me.breakgim.runa.desktop',
  install_dir: datadir / 'applications'
)

desktop_utils = find_program('desktop-file-validate', required: false)
if desktop_utils.found()
  test(
    'Validate desktop file',
    desktop_utils,
    args: [meson.current_source_dir() / 'me.breakgim.runa.desktop.in']
  )
endif

install_data(
  'me.breakgim.runa.metainfo.xml',
  install_dir: datadir / 'metainfo'
)

ascli_exe = find_program('appstreamcli', required: false)
if ascli_exe.found()
  test(
    'Validate metainfo file',
    ascli_exe,
    args: [
      'validate',
      '--no-net',
      '--pedantic',
      meson.current_source_dir() / 'me.breakgim.runa.metainfo.xml'
    ]
  )
endif

install_data(
  'me.breakgim.runa.gschema.xml',
  install_dir: datadir / 'glib-2.0' / 'schemas'
)

compile_schemas = find_program('glib-compile-schemas', required: false)
if compile_schemas.found()
  test(
    'Validate schema file',
    compile_schemas,
    args: ['--strict', '--dry-run', meson.current_source_dir()]
  )
endif

install_data(
  'me.breakgim.runa.svg',
  install_dir: datadir / 'icons' / 'hicolor' / 'scalable' / 'apps'
)
