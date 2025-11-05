from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import pybind11

ext_modules = [
	Extension(
		name = "CTF_Lib.Cryptography.LinearAlgebra.linear_equation_solver_GF2_impl",
		sources = ["CTF_Lib/Cryptography/LinearAlgebra/linear_equation_solver_GF2_impl.cpp"],
		include_dirs = [
			pybind11.get_include(),
			"CTF_Lib",
		],
		extra_compile_args = ["-std=c++26", "-O3", "-march=native"],
		language = "c++",
	),
	Extension(
		name = "CTF_Lib.Cryptography.Hash.hash_impl",
		sources = ["CTF_Lib/Cryptography/Hash/hash_impl.cpp"],
		include_dirs = [
			pybind11.get_include(),
			"CTF_Lib",
		],
		extra_compile_args = ["-std=c++26", "-O3", "-march=native"],
		language = "c++",
	),
	Extension(
		name = "CTF_Lib.Cryptography.EllipticCurve.ECDLP_bounded_impl",
		sources = ["CTF_Lib/Cryptography/EllipticCurve/ECDLP_bounded_impl.cpp"],
		include_dirs = [
			pybind11.get_include(),
			"CTF_Lib",
		],
		extra_compile_args = ["-std=c++26", "-O3", "-march=native"],
		libraries = ["gmpxx", "gmp"],
		language = "c++",
	),
]

setup(
	ext_modules=ext_modules,
)
