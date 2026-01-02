pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()
moduledir = pkgdatadir / 'runa'

configure_file(
  input: 'runa.in',
  output: 'runa',
  configuration: {
    'PYTHON': python3.full_path(),
    'pkgdatadir': pkgdatadir,
  },
  install: true,
  install_dir: bindir,
  install_mode: 'rwxr-xr-x'
)

install_data('main.py',
  install_dir: moduledir
)
