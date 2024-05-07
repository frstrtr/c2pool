from conan import ConanFile
from conan.tools.cmake import cmake_layout
# from conan.tools.cmake import CMakeToolchain

required_conan_version = '>=2.3.0'

class C2PoolConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"
    generators = "CMakeDeps", "CMakeToolchain"

    options = {"build_type": ["Debug", "Release"]}
    default_options = {"build_type": "Debug"}

    def requirements(self):
        self.requires("boost/1.78.0", transitive_headers=True)
        self.requires("nlohmann_json/3.11.3")

    def layout(self):
        cmake_layout(self)