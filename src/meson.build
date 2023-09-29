#
# Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA-MPIID', 'C', 'CPP',
	# Get version number from file.
	# Fallback to "more" for Windows compatibility.
	version: run_command(find_program('cat', 'more'),
		files('VERSION')).stdout().strip(),
	license: 'BSD',
	default_options: ['buildtype=debug',
			  'default_library=static'],
	meson_version: '>= 0.47.1'
)

# set up some global vars for compiler, platform, configuration, etc.
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')

add_project_arguments('-DALLOW_EXPERIMENTAL_API', language: 'c')
add_project_arguments('-D_GNU_SOURCE', language: 'c')

if host_machine.cpu_family().startswith('x86')
	add_project_arguments('-march=native', language: 'c')
	add_project_arguments('-mavx', language: 'c')
	arch_subdir = 'x86'
elif host_machine.cpu_family().startswith('arm') or host_machine.cpu_family().startswith('aarch')
	arch_subdir = 'arm'
elif host_machine.cpu_family().startswith('ppc')
	arch_subdir = 'ppc'
endif

# Uncomment this line to remove warnings of experimental compile
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')


app_dependencies = []
libdpdk_dep = dependency('libdpdk', required : true)
if not libdpdk_dep.found()
	error('please set PKG_CONFIG_PATH to dpdk packages path, for further instructions check DOCA manuals')
endif
app_dependencies += libdpdk_dep
app_dependencies += dependency('threads', required : true)
app_dependencies += dependency('doca', required : true)

sources = [
	'mpiid_pkt.c',
	'mpiid_port.c',
	'mpiid.c',
	'logger.c',
	'./../common/src/flow_offload.c',
	'./../common/src/utils.c',
]

inc_dir = include_directories(
	'./../common/src', 
	'./../mpich/include', 
	'/opt/mellanox/doca/include', 
	'/usr/include',
	'/opt/mellanox/doca/applications/common/src/'
)

executable('mpiid', sources, dependencies : app_dependencies, include_directories : inc_dir, install: false)

