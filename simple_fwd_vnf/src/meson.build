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

project('DOCA-SIMPLE-FWD', 'C', 'CPP',
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

libdpdk_dep = dependency('libdpdk', required : false)
if not libdpdk_dep.found()
	error('please set PKG_CONFIG_PATH to dpdk packages path, for further instructions check DOCA manuals')
endif
thread_dep = dependency('threads', required : true)
libflow_utils_dep = dependency('doca-utils', required : true)
libflow_dep = dependency('doca-flow', required : true)
libcommon_dep = dependency('doca-common', required : true)

sources = [
	'simple_fwd_ft.c',
	'simple_fwd_pkt.c',
	'simple_fwd_port.c',
	'simple_fwd_vnf.c',
	'simple_fwd.c',
	'./../../common/src/flow_offload.c',
	'./../../common/src/utils.c',
]

common_dir = include_directories('./../../common/src')

executable('doca_simple_fwd_vnf', sources, dependencies : [libcommon_dep, libflow_dep, libflow_utils_dep, libdpdk_dep, thread_dep], include_directories : [common_dir], install: false)

