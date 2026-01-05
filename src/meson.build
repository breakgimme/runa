pkgdatadir = get_option('prefix') / get_option('datadir') / meson.project_name()

configure_file(
  input: 'runa.in',
  output: 'runa',
  configuration: {
    'PYTHON': python3.full_path(),
    'VERSION': meson.project_version(),
  },
  install: true,
  install_dir: bindir,
  install_mode: 'rwxr-xr-x'
)

python3.install_sources(
  '__init__.py',
  'main.py',
  'auth.py',
  subdir: 'runa',
)
