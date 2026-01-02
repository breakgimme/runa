project('runa',
  version: '0.1.0',
  meson_version: '>= 0.59.0',
)

python = import('python')
gnome = import('gnome')

python3 = python.find_installation('python3')

prefix = get_option('prefix')
bindir = prefix / get_option('bindir')
datadir = prefix / get_option('datadir')
pkgdatadir = datadir / meson.project_name()

subdir('data')
subdir('src')

gnome.post_install(
  glib_compile_schemas: true,
  gtk_update_icon_cache: true,
  update_desktop_database: true,
)
