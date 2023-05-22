#*******************************************************************************
# This file is part of MADCAT, the Mass Attack Detection Acceptance Tool.
#    MADCAT is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    MADCAT is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    You should have received a copy of the GNU General Public License
#    along with MADCAT.  If not, see <http://www.gnu.org/licenses/>.
#
# Diese Datei ist Teil von MADCAT, dem Mass Attack Detection Acceptance Tool.
#    MADCAT ist Freie Software: Sie können es unter den Bedingungen
#    der GNU General Public License, wie von der Free Software Foundation,
#    Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
#    veröffentlichten Version, weiter verteilen und/oder modifizieren.
#    MADCAT wird in der Hoffnung, dass es nützlich sein wird, aber
#    OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
#    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK.
#    Siehe die GNU General Public License für weitere Details.
#    Sie sollten eine Kopie der GNU General Public License zusammen mit diesem
#    Programm erhalten haben. Wenn nicht, siehe <https://www.gnu.org/licenses/>.
#*******************************************************************************/
#
#BSI 2020-2021
#


# add fuzz executables 
add_executable(fuzz_example fuzz_example.cpp)

target_link_libraries(fuzz_example
  MadCatHelper
  TcpIpPortMonCore
  TcpProxyCore
  DictCCore
 -fsanitize=address,fuzzer,undefined,signed-integer-overflow,bool,pointer-overflow,null,alignment -fno-omit-frame-pointer
 -fsanitize-coverage=edge,indirect-calls,trace-cmp,trace-div,trace-gep
)
#/opt/llvm-dev/lib/clang/16/lib/x86_64-unknown-linux-gnu/libclang_rt.fuzzer.a
#-v
# compile options
#target_compile_options(fuzz_example PUBLIC -g -fPIC -fsanitize=address,fuzzer,undefined,signed-integer-overflow,bool,pointer-overflow -fsanitize-coverage=indirect-calls,trace-cmp,trace-div,trace-gep -fno-omit-frame-pointer)

