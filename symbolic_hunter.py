#!/usr/bin/env python3
"""
SymbolicHunter - Comprehensive Symbolic Execution Analysis Tool
Automatically detects vulnerabilities and analyzes binaries using angr
"""

import angr
import claripy
import sys
import argparse
from collections import defaultdict
import logging
from datetime import datetime
import json

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SymbolicHunter:
    def __init__(self, binary_path, verbose=False, max_states=1000, timeout=300):
        self.binary_path = binary_path
        self.verbose = verbose
        self.max_states = max_states
        self.timeout = timeout

        # Results storage
        self.vulnerabilities = defaultdict(list)
        self.interesting_paths = []
        self.constraints_found = []
        self.unconstrained_paths = []
        self.dangerous_functions = []
        self.cfg = None
        self.functions_found = []
        self.winning_inputs = []  # Inputs that reach interesting locations
        self.coverage_info = set()  # Track code coverage
        self.anti_analysis_detected = []  # Anti-debugging/anti-analysis techniques
        self.exploit_candidates = []  # Potential exploits with PoC inputs
        self.unique_vulns = {}  # Deduplicated vulnerabilities
        self.taint_sinks = []  # Tainted data reaching dangerous sinks
        self.taint_sources = set()  # Track all taint sources (stdin, argv, etc.)
        self.data_flows = []  # Track input → output data flows

        # Statistics
        self.stats = {
            'paths_explored': 0,
            'states_analyzed': 0,
            'constraints_solved': 0,
            'time_elapsed': 0,
            'functions_discovered': 0,
            'basic_blocks': 0,
            'code_coverage': 0
        }

        # Setup logging
        if verbose:
            logging.getLogger('angr').setLevel(logging.INFO)
        else:
            logging.getLogger('angr').setLevel(logging.WARNING)

        print(f"{Colors.BOLD}{Colors.CYAN}[*] Loading binary: {binary_path}{Colors.END}")

        # Load the binary with angr
        try:
            self.project = angr.Project(binary_path, auto_load_libs=False)
            print(f"{Colors.GREEN}[+] Binary loaded successfully{Colors.END}")
            print(f"    Architecture: {self.project.arch.name}")
            print(f"    Entry point: {hex(self.project.entry)}")
            print(f"    Base address: {hex(self.project.loader.main_object.min_addr)}")

            # Perform initial CFG analysis with angr
            print(f"\n{Colors.CYAN}[*] Performing CFG analysis...{Colors.END}")
            try:
                self.cfg = self.project.analyses.CFGFast()
                self.stats['functions_discovered'] = len(self.cfg.functions)
                self.stats['basic_blocks'] = len(list(self.cfg.graph.nodes()))
                print(f"{Colors.GREEN}[+] CFG analysis complete{Colors.END}")
                print(f"    Functions discovered: {self.stats['functions_discovered']}")
                print(f"    Basic blocks: {self.stats['basic_blocks']}")

                # Identify dangerous functions using angr's knowledge base
                self.identify_dangerous_functions()

            except Exception as e:
                print(f"{Colors.YELLOW}[!] CFG analysis failed: {e}{Colors.END}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()

        except Exception as e:
            print(f"{Colors.RED}[!] Failed to load binary: {e}{Colors.END}")
            sys.exit(1)

    def print_header(self):
        """Print tool header"""
        header = f"""
{Colors.BOLD}{Colors.CYAN}
╔═══════════════════════════════════════════════════════════╗
║           SymbolicHunter - angr Analysis Tool             ║
║     Comprehensive Symbolic Execution Vulnerability        ║
║              Detection and Path Analysis                  ║
╚═══════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(header)

    def identify_dangerous_functions(self):
        """Identify dangerous API calls using angr CFG"""
        if not self.cfg:
            return

        dangerous_apis = {
            'memory': ['VirtualAlloc', 'VirtualProtect', 'HeapAlloc', 'malloc', 'calloc', 'realloc'],
            'file': ['CreateFile', 'WriteFile', 'fopen', 'fwrite'],
            'process': ['CreateProcess', 'WinExec', 'ShellExecute', 'system', 'exec', 'popen'],
            'library': ['LoadLibrary', 'GetProcAddress', 'dlopen', 'dlsym'],
            'network': ['connect', 'send', 'recv', 'WSAStartup', 'socket'],
            'string': ['strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf', 'scanf'],
            'format': ['printf', 'fprintf', 'vprintf', 'vfprintf', 'snprintf'],
            'anti_debug': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess'],
            'anti_vm': ['cpuid', 'rdtsc'],
            'crypto': ['CryptEncrypt', 'CryptDecrypt', 'BCryptEncrypt']
        }

        print(f"\n{Colors.CYAN}[*] Scanning for dangerous API calls...{Colors.END}")

        api_categories = defaultdict(list)

        for func_addr, func in self.cfg.functions.items():
            func_name = func.name

            # Check each category
            for category, apis in dangerous_apis.items():
                for dangerous in apis:
                    if dangerous.lower() in func_name.lower():
                        self.dangerous_functions.append({
                            'name': func_name,
                            'address': hex(func_addr),
                            'type': dangerous,
                            'category': category
                        })
                        api_categories[category].append(func_name)

                        # Flag anti-analysis techniques
                        if category in ['anti_debug', 'anti_vm']:
                            self.anti_analysis_detected.append({
                                'technique': category,
                                'function': func_name,
                                'address': hex(func_addr)
                            })

        if self.dangerous_functions:
            print(f"{Colors.YELLOW}[!] Found {len(self.dangerous_functions)} dangerous API calls{Colors.END}")

            # Show summary by category
            for category, funcs in api_categories.items():
                color = Colors.RED if category in ['process', 'anti_debug', 'anti_vm'] else Colors.YELLOW
                print(f"    {color}[{category.upper()}]{Colors.END} {len(funcs)} calls")

            if self.verbose:
                for func in self.dangerous_functions[:10]:
                    print(f"    - {func['name']} at {func['address']}")
        else:
            print(f"{Colors.GREEN}[+] No known dangerous APIs detected{Colors.END}")

        # Warn about anti-analysis
        if self.anti_analysis_detected:
            print(f"\n{Colors.RED}[!!!] Anti-Analysis Techniques Detected!{Colors.END}")
            print(f"      This binary may evade debugging/analysis")
            for tech in self.anti_analysis_detected:
                print(f"      - {tech['technique']}: {tech['function']} at {tech['address']}")

    def check_buffer_overflow(self, state):
        """Detect potential buffer overflow vulnerabilities"""
        try:
            # Check for symbolic memory operations that could overflow
            # Look at symbolic registers that might be used for memory access
            if self.project.arch.name == 'AMD64':
                regs_to_check = [state.regs.rax, state.regs.rbx, state.regs.rcx, 
                                state.regs.rdx, state.regs.rsi, state.regs.rdi]
            else:
                regs_to_check = [state.regs.eax, state.regs.ebx, state.regs.ecx, 
                                state.regs.edx, state.regs.esi, state.regs.edi]

            for reg in regs_to_check:
                if reg.symbolic:
                    # Check if this could point to a large memory address (overflow)
                    if state.solver.satisfiable(extra_constraints=[reg > 0x7fff0000]):
                        self.vulnerabilities['buffer_overflow'].append({
                            'address': hex(state.addr),
                            'register': str(reg),
                            'description': 'Symbolic pointer could overflow buffer bounds'
                        })
                        break  # Only report once per state
        except Exception as e:
            if self.verbose:
                print(f"    Buffer overflow check error: {e}")

    def check_integer_overflow(self, state):
        """Detect potential integer overflow vulnerabilities"""
        try:
            # Look for arithmetic operations on symbolic values
            for var in state.solver.get_variables('file_/dev/stdin'):
                # Check if we can make this overflow
                if state.solver.satisfiable(extra_constraints=[var > 0x7fffffff]):
                    self.vulnerabilities['integer_overflow'].append({
                        'address': hex(state.addr),
                        'variable': str(var),
                        'description': 'Symbolic integer can overflow'
                    })
        except Exception as e:
            if self.verbose:
                print(f"    Integer overflow check error: {e}")

    def check_format_string(self, state):
        """Detect format string vulnerabilities"""
        try:
            # Check if we're at a printf-like function with symbolic format string
            ip = state.addr
            block = self.project.factory.block(ip)

            # Look for calls to printf, sprintf, etc.
            dangerous_funcs = ['printf', 'sprintf', 'fprintf', 'snprintf']

            for insn in block.capstone.insns:
                if insn.mnemonic == 'call':
                    # Check if format argument is symbolic
                    if self.project.arch.name == 'AMD64':
                        fmt_arg = state.regs.rsi  # Second argument in x64
                    else:
                        fmt_arg = state.regs.esi

                    if fmt_arg.symbolic:
                        self.vulnerabilities['format_string'].append({
                            'address': hex(state.addr),
                            'description': 'Symbolic format string argument'
                        })
        except Exception as e:
            if self.verbose:
                print(f"    Format string check error: {e}")

    def check_null_deref(self, state):
        """Detect NULL pointer dereference"""
        try:
            # Check for symbolic pointers that could be NULL
            if self.project.arch.name == 'AMD64':
                regs_to_check = [state.regs.rax, state.regs.rbx, state.regs.rcx, 
                                state.regs.rdx, state.regs.rsi, state.regs.rdi]
            else:
                regs_to_check = [state.regs.eax, state.regs.ebx, state.regs.ecx, state.regs.edx]

            for reg in regs_to_check:
                if reg.symbolic and state.solver.satisfiable(extra_constraints=[reg == 0]):
                    self.vulnerabilities['null_deref'].append({
                        'address': hex(state.addr),
                        'register': str(reg),
                        'description': 'Register can be NULL and may be dereferenced'
                    })
        except Exception as e:
            if self.verbose:
                print(f"    NULL deref check error: {e}")

    def check_division_by_zero(self, state):
        """Detect division by zero"""
        try:
            ip = state.addr
            block = self.project.factory.block(ip)

            for insn in block.capstone.insns:
                if insn.mnemonic in ['div', 'idiv']:
                    # Check if divisor can be zero
                    if self.project.arch.name == 'AMD64':
                        divisor = state.regs.rcx
                    else:
                        divisor = state.regs.ecx

                    if divisor.symbolic and state.solver.satisfiable(extra_constraints=[divisor == 0]):
                        self.vulnerabilities['div_by_zero'].append({
                            'address': hex(state.addr),
                            'description': 'Division by zero possible'
                        })
        except Exception as e:
            if self.verbose:
                print(f"    Division by zero check error: {e}")

    def check_unconstrained(self, state):
        """Detect unconstrained execution (potential code execution)"""
        try:
            if state.regs.ip.symbolic:
                # Instruction pointer is symbolic - critical vulnerability
                self.vulnerabilities['unconstrained_execution'].append({
                    'address': hex(state.addr),
                    'description': 'Instruction pointer is symbolic - possible code execution',
                    'severity': 'CRITICAL'
                })
                self.unconstrained_paths.append(state)
        except Exception as e:
            if self.verbose:
                print(f"    Unconstrained check error: {e}")

    def check_taint_flow(self, state):
        """Check if tainted data reaches dangerous sinks (TAINT ANALYSIS)"""
        try:
            # Define dangerous sink functions where tainted data could cause issues
            dangerous_sinks = {
                'system': 'Command Injection',
                'exec': 'Command Injection', 
                'popen': 'Command Injection',
                'CreateProcess': 'Command Injection',
                'WinExec': 'Command Injection',
                'ShellExecute': 'Command Injection',
                'strcpy': 'Buffer Overflow',
                'strcat': 'Buffer Overflow',
                'sprintf': 'Buffer Overflow',
                'gets': 'Buffer Overflow',
                'scanf': 'Buffer Overflow',
                'memcpy': 'Buffer Overflow',
                'printf': 'Format String',
                'fprintf': 'Format String',
                'snprintf': 'Format String',
                'LoadLibrary': 'Arbitrary Library Load',
                'dlopen': 'Arbitrary Library Load',
                'fopen': 'Arbitrary File Access',
                'open': 'Arbitrary File Access',
                'CreateFile': 'Arbitrary File Access'
            }

            # Get current function name if available
            current_func = None
            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func:
                    current_func = func.name

            # Check if we're at a dangerous sink
            if current_func:
                for sink, vuln_type in dangerous_sinks.items():
                    if sink.lower() in current_func.lower():
                        # Now check if arguments are tainted (symbolic from our input)
                        tainted = False
                        tainted_args = []

                        # Check function arguments for taint
                        if self.project.arch.name == 'AMD64':
                            # x64 calling convention: RDI, RSI, RDX, RCX, R8, R9
                            arg_regs = [state.regs.rdi, state.regs.rsi, state.regs.rdx, 
                                       state.regs.rcx, state.regs.r8, state.regs.r9]
                        else:
                            # x86 calling convention: stack-based, but check common registers
                            arg_regs = [state.regs.eax, state.regs.ecx, state.regs.edx]

                        for idx, arg in enumerate(arg_regs):
                            if arg.symbolic:
                                # Check if this symbolic value comes from our input
                                arg_vars = state.solver.get_variables(arg)
                                for var_name in arg_vars:
                                    if any(src in str(var_name) for src in ['stdin', 'arg', 'file']):
                                        tainted = True
                                        tainted_args.append(f'arg{idx}')

                        # Also check memory pointed to by arguments (for string functions)
                        for idx, arg in enumerate(arg_regs[:3]):  # Check first 3 args
                            try:
                                if not arg.symbolic and state.solver.is_true(arg != 0):
                                    # Try to read memory at this address
                                    mem_val = state.memory.load(arg, 8)
                                    if mem_val.symbolic:
                                        mem_vars = state.solver.get_variables(mem_val)
                                        for var_name in mem_vars:
                                            if any(src in str(var_name) for src in ['stdin', 'arg', 'file']):
                                                tainted = True
                                                tainted_args.append(f'*arg{idx}')
                            except:
                                pass

                        if tainted:
                            # Found tainted data at dangerous sink!
                            sink_info = {
                                'address': hex(state.addr),
                                'function': current_func,
                                'vulnerability_type': vuln_type,
                                'tainted_arguments': tainted_args,
                                'description': f'Tainted input reaches {sink} - potential {vuln_type}'
                            }

                            # Try to generate concrete exploit input
                            try:
                                if state.solver.satisfiable():
                                    stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                                    if stdin_vars:
                                        exploit_input = state.solver.eval(stdin_vars[0], cast_to=bytes)
                                        sink_info['exploit_input'] = exploit_input[:100]
                            except:
                                pass

                            self.taint_sinks.append(sink_info)

                            # Also add to vulnerabilities
                            self.vulnerabilities['taint_to_sink'].append(sink_info)

                            if self.verbose:
                                print(f"{Colors.RED}[TAINT] {vuln_type} at {hex(state.addr)}: "
                                      f"{current_func}({', '.join(tainted_args)}){Colors.END}")

        except Exception as e:
            if self.verbose:
                print(f"    Taint analysis error: {e}")

    def track_data_flow(self, state):
        """Track data flow from input to output"""
        try:
            # Check for output operations (write, send, print, etc.)
            output_funcs = ['write', 'send', 'printf', 'fprintf', 'puts', 'fwrite']

            if self.cfg:
                func = self.cfg.functions.get(state.addr)
                if func:
                    current_func = func.name

                    for output_func in output_funcs:
                        if output_func in current_func.lower():
                            # Check if output data is tainted (comes from input)
                            if self.project.arch.name == 'AMD64':
                                output_arg = state.regs.rsi  # Usually second arg is data
                            else:
                                output_arg = state.regs.ecx

                            if output_arg.symbolic:
                                arg_vars = state.solver.get_variables(output_arg)
                                for var_name in arg_vars:
                                    if any(src in str(var_name) for src in ['stdin', 'arg', 'file']):
                                        # Found input → output flow!
                                        self.data_flows.append({
                                            'address': hex(state.addr),
                                            'function': current_func,
                                            'flow': 'input → output',
                                            'description': f'User input directly influences output at {current_func}'
                                        })
                                        break
        except:
            pass

    def analyze_state(self, state):
        """Run all vulnerability checks on a state"""
        self.stats['states_analyzed'] += 1

        # Track code coverage
        self.coverage_info.add(state.addr)

        # Run all checks (with deduplication)
        addr_key = state.addr

        # Only check each address once to reduce noise
        if addr_key not in self.unique_vulns:
            self.unique_vulns[addr_key] = True

            self.check_buffer_overflow(state)
            self.check_integer_overflow(state)
            self.check_format_string(state)
            self.check_null_deref(state)
            self.check_division_by_zero(state)
            self.check_unconstrained(state)

        # TAINT ANALYSIS - always check regardless of deduplication
        self.check_taint_flow(state)
        self.track_data_flow(state)

        # Track taint sources
        for var in state.solver.get_variables():
            if any(src in str(var) for src in ['stdin', 'arg', 'file']):
                self.taint_sources.add(str(var))

        # Check if we reached a dangerous function
        for dangerous in self.dangerous_functions:
            if state.addr == int(dangerous['address'], 16):
                try:
                    # Try to generate input that reaches this dangerous function
                    if state.solver.satisfiable():
                        stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                        if stdin_vars:
                            concrete_input = state.solver.eval(stdin_vars[0], cast_to=bytes)
                            self.exploit_candidates.append({
                                'target_function': dangerous['name'],
                                'address': dangerous['address'],
                                'category': dangerous.get('category', 'unknown'),
                                'input': concrete_input[:100],
                                'description': f"Input reaches {dangerous['name']} - potential exploit vector"
                            })
                except:
                    pass

        # Try to generate concrete input for interesting states
        if len(state.solver.constraints) > 5:  # Has interesting constraints
            try:
                # Attempt to solve for a concrete input
                stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                if stdin_vars and state.solver.satisfiable():
                    # Get a concrete value for stdin
                    concrete_stdin = state.solver.eval(stdin_vars[0], cast_to=bytes)
                    self.winning_inputs.append({
                        'address': hex(state.addr),
                        'input': concrete_stdin[:50],  # First 50 bytes
                        'num_constraints': len(state.solver.constraints)
                    })
            except:
                pass

        # Store interesting constraints (sample only)
        if len(state.solver.constraints) > 0 and len(self.constraints_found) < 100:
            self.constraints_found.append({
                'address': hex(state.addr),
                'num_constraints': len(state.solver.constraints),
                'constraints': [str(c) for c in list(state.solver.constraints)[:3]]  # First 3
            })

    def explore_binary(self, target_function=None):
        """Main exploration routine using angr simulation manager"""
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Starting symbolic execution with angr...{Colors.END}")
        print(f"    Max states: {self.max_states}")
        print(f"    Timeout: {self.timeout}s\n")

        # Create initial state with symbolic stdin using angr - simplified approach
        state = self.project.factory.entry_state(
            add_options={
                angr.options.LAZY_SOLVES,
            }
        )

        # Make stdin symbolic with angr's claripy - using correct SimFile API
        stdin_size = 200  # bytes of symbolic input
        stdin_data = claripy.BVS('stdin', 8 * stdin_size)

        # Create a proper SimFile for stdin
        stdin_file = angr.storage.SimFile('stdin', content=stdin_data, size=stdin_size)

        # Replace stdin with our symbolic file
        state.fs.insert('stdin', stdin_file)
        state.posix.stdin = stdin_file

        # Add symbolic command line arguments if not Windows
        if self.project.loader.main_object.os != 'windows':
            arg1 = claripy.BVS('arg1', 8 * 100)
            state.posix.argv = [self.project.filename, arg1]
        else:
            print(f"{Colors.CYAN}[*] Detected Windows PE binary{Colors.END}")

        # Create angr simulation manager with exploration techniques
        simgr = self.project.factory.simulation_manager(state)

        # Set up find/avoid addresses if targeting specific function
        find_addr = None
        if target_function:
            print(f"{Colors.CYAN}[*] Searching for function: {target_function}{Colors.END}")
            for func_addr, func in self.cfg.functions.items():
                if target_function.lower() in func.name.lower():
                    find_addr = func_addr
                    print(f"{Colors.GREEN}[+] Found target: {func.name} at {hex(func_addr)}{Colors.END}")
                    break

            if not find_addr:
                print(f"{Colors.YELLOW}[!] Function '{target_function}' not found in binary{Colors.END}")

        # Add exploration technique to prioritize dangerous functions
        if self.dangerous_functions:
            dangerous_addrs = [int(f['address'], 16) for f in self.dangerous_functions]
            print(f"{Colors.CYAN}[*] Prioritizing {len(dangerous_addrs)} dangerous functions{Colors.END}")

            # Use DFS to explore deeper and find functions
            try:
                from angr.exploration_techniques import DFS
                simgr.use_technique(DFS())
            except:
                pass

        print(f"{Colors.CYAN}[*] Using angr exploration strategies...{Colors.END}\n")

        start_time = datetime.now()
        step_count = 0
        found_target = False

        try:
            while len(simgr.active) > 0 and step_count < self.max_states:

                # Check if we found target function
                if find_addr and not found_target:
                    for state in simgr.active:
                        if state.addr == find_addr:
                            print(f"\n{Colors.GREEN}[!!!] Reached target function at {hex(find_addr)}!{Colors.END}")
                            found_target = True
                            # Generate input that reaches this function
                            try:
                                if state.solver.satisfiable():
                                    stdin_vars = [v for v in state.solver.get_variables() if 'stdin' in str(v)]
                                    if stdin_vars:
                                        winning_input = state.solver.eval(stdin_vars[0], cast_to=bytes)
                                        print(f"{Colors.MAGENTA}[+] Input to reach target:{Colors.END}")
                                        print(f"    Hex: {winning_input[:50].hex()}")
                                        print(f"    ASCII: {repr(winning_input[:50])}\n")

                                        self.exploit_candidates.append({
                                            'target_function': target_function,
                                            'address': hex(find_addr),
                                            'category': 'target',
                                            'input': winning_input[:100],
                                            'description': f'Input reaches target function {target_function}'
                                        })
                            except:
                                pass

                # Step through execution using angr
                simgr.step()
                step_count += 1
                self.stats['paths_explored'] = len(simgr.active) + len(simgr.deadended)

                # Analyze each active state with angr
                for state in simgr.active:
                    self.analyze_state(state)

                # Check deadended states (paths that terminated)
                for state in simgr.deadended:
                    self.analyze_state(state)

                # Handle errored states (paths that crashed - potentially vulnerable!)
                for errored_state in simgr.errored:
                    if hasattr(errored_state, 'state'):
                        self.vulnerabilities['crashed_paths'].append({
                            'address': hex(errored_state.state.addr),
                            'error': str(errored_state.error)[:200],
                            'description': 'Path resulted in error - possible vulnerability'
                        })

                # Progress update
                if step_count % 50 == 0:
                    elapsed = (datetime.now() - start_time).total_seconds()
                    active = len(simgr.active)
                    dead = len(simgr.deadended)
                    errors = len(simgr.errored)
                    uncon = len(simgr.unconstrained)

                    print(f"{Colors.CYAN}[*] Step {step_count}: "
                          f"Active={active}, Dead={dead}, Error={errors}, Uncon={uncon}, "
                          f"Exploits={len(self.exploit_candidates)}, Time={elapsed:.1f}s{Colors.END}")

                # Timeout check
                if (datetime.now() - start_time).total_seconds() > self.timeout:
                    print(f"\n{Colors.YELLOW}[!] Timeout reached{Colors.END}")
                    break

                # Prune if too many states (angr memory management)
                if len(simgr.active) > 100:
                    print(f"{Colors.YELLOW}[!] Pruning states (too many active paths){Colors.END}")
                    # Keep only the first 50 states
                    simgr.active = simgr.active[:50]

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Analysis interrupted by user{Colors.END}")
        except Exception as e:
            print(f"\n{Colors.RED}[!] Analysis error: {e}{Colors.END}")
            if self.verbose:
                import traceback
                traceback.print_exc()

        self.stats['time_elapsed'] = (datetime.now() - start_time).total_seconds()

        # Calculate code coverage
        if self.stats['basic_blocks'] > 0:
            self.stats['code_coverage'] = (len(self.coverage_info) / self.stats['basic_blocks']) * 100

        # Final sweep - analyze all remaining states in all stashes
        print(f"\n{Colors.CYAN}[*] Performing final analysis of all paths...{Colors.END}")

        for stash_name in ['active', 'deadended', 'errored', 'unconstrained']:
            stash = getattr(simgr, stash_name, [])
            for item in stash:
                # Handle errored states differently
                if stash_name == 'errored':
                    if hasattr(item, 'state'):
                        self.analyze_state(item.state)
                else:
                    self.analyze_state(item)

        self.stats['states_analyzed'] = len(simgr.deadended) + len(simgr.active)

        # Report on target search
        if target_function:
            if found_target:
                print(f"{Colors.GREEN}[+] Successfully found path to '{target_function}'!{Colors.END}")
            else:
                print(f"{Colors.YELLOW}[!] Could not find path to '{target_function}' within constraints{Colors.END}")

    def print_results(self):
        """Print comprehensive analysis results"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}╔════════════════════════════════════════════════════════╗")
        print(f"║                  ANALYSIS COMPLETE                     ║")
        print(f"╚════════════════════════════════════════════════════════╝{Colors.END}\n")

        # Statistics
        print(f"{Colors.BOLD}{Colors.CYAN}[*] Execution Statistics:{Colors.END}")
        print(f"    Paths explored: {self.stats['paths_explored']}")
        print(f"    States analyzed: {self.stats['states_analyzed']}")
        print(f"    Time elapsed: {self.stats['time_elapsed']:.2f}s")
        print(f"    Constraints found: {len(self.constraints_found)}")

        # Vulnerability summary
        total_vulns = sum(len(v) for v in self.vulnerabilities.values())
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[*] Vulnerability Summary:{Colors.END}")
        print(f"    Total issues found: {total_vulns}\n")

        # Detailed vulnerabilities
        if total_vulns > 0:
            for vuln_type, instances in self.vulnerabilities.items():
                if instances:
                    severity_color = Colors.RED if vuln_type == 'unconstrained_execution' else Colors.YELLOW
                    print(f"{Colors.BOLD}{severity_color}[!] {vuln_type.upper().replace('_', ' ')} "
                          f"({len(instances)} found):{Colors.END}")

                    for idx, vuln in enumerate(instances[:5], 1):  # Show first 5
                        print(f"    {idx}. Address: {vuln.get('address', 'N/A')}")
                        print(f"       {vuln.get('description', 'No description')}")
                        if 'severity' in vuln:
                            print(f"       Severity: {Colors.RED}{vuln['severity']}{Colors.END}")

                    if len(instances) > 5:
                        print(f"    ... and {len(instances) - 5} more")
                    print()
        else:
            print(f"    {Colors.GREEN}No vulnerabilities detected{Colors.END}\n")

        # Interesting constraints
        if self.constraints_found and self.verbose:
            print(f"{Colors.BOLD}{Colors.MAGENTA}[*] Interesting Constraints (sample):{Colors.END}")
            for constraint_info in self.constraints_found[:3]:
                print(f"    Address: {constraint_info['address']}")
                print(f"    Number of constraints: {constraint_info['num_constraints']}")
                for c in constraint_info['constraints']:
                    print(f"      - {c[:80]}...")
            print()

        # Unconstrained paths (most critical)
        if self.unconstrained_paths:
            print(f"{Colors.BOLD}{Colors.RED}[!!!] CRITICAL: Unconstrained Execution Paths Found!{Colors.END}")
            print(f"      This may allow arbitrary code execution")
            print(f"      Affected states: {len(self.unconstrained_paths)}\n")

    def export_results(self, output_file):
        """Export results to JSON"""
        results = {
            'binary': self.binary_path,
            'timestamp': datetime.now().isoformat(),
            'statistics': self.stats,
            'vulnerabilities': dict(self.vulnerabilities),
            'dangerous_functions': self.dangerous_functions,
            'anti_analysis': self.anti_analysis_detected,
            'taint_analysis': {
                'sinks_found': len(self.taint_sinks),
                'tainted_sinks': [
                    {
                        'address': sink['address'],
                        'function': sink['function'],
                        'type': sink['vulnerability_type'],
                        'tainted_args': sink['tainted_arguments'],
                        'exploit_hex': sink.get('exploit_input', b'').hex() if 'exploit_input' in sink else None
                    } for sink in self.taint_sinks
                ],
                'data_flows': self.data_flows,
                'taint_sources': list(self.taint_sources)
            },
            'exploit_candidates': [
                {
                    'target_function': e['target_function'],
                    'address': e['address'],
                    'category': e['category'],
                    'input_hex': e['input'].hex(),
                    'description': e['description']
                } for e in self.exploit_candidates
            ],
            'constraints_sample': self.constraints_found[:10],
            'coverage': {
                'percentage': self.stats['code_coverage'],
                'addresses_hit': len(self.coverage_info),
                'total_blocks': self.stats['basic_blocks']
            }
        }

        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        print(f"{Colors.GREEN}[+] Results exported to: {output_file}{Colors.END}")

    def generate_poc_script(self, output_file):
        """Generate a Python PoC script for testing exploits"""
        if not self.exploit_candidates:
            print(f"{Colors.YELLOW}[!] No exploit candidates to generate PoC{Colors.END}")
            return

        poc_script = f'''#!/usr/bin/env python3
"""
Proof of Concept Exploit Script
Generated by SymbolicHunter
Target: {self.binary_path}
Generated: {datetime.now().isoformat()}

WARNING: Use only for authorized security testing!
"""

import subprocess
import sys

def test_exploit(exploit_name, input_data, description):
    """Test an exploit candidate"""
    print(f"[*] Testing: {{exploit_name}}")
    print(f"    {{description}}")
    print(f"    Input length: {{len(input_data)}} bytes")

    try:
        # Write input to file
        with open('exploit_input.bin', 'wb') as f:
            f.write(input_data)

        # Run the target with the exploit input
        # Adjust this command based on how the binary accepts input
        result = subprocess.run(
            ['{self.binary_path}'],
            stdin=open('exploit_input.bin', 'rb'),
            capture_output=True,
            timeout=5
        )

        print(f"    Return code: {{result.returncode}}")
        if result.stdout:
            print(f"    Stdout: {{result.stdout[:100]}}")
        if result.stderr:
            print(f"    Stderr: {{result.stderr[:100]}}")
        print()

    except subprocess.TimeoutExpired:
        print(f"    [!] Process timeout - possible infinite loop or hang")
    except Exception as e:
        print(f"    [!] Error: {{e}}")
    print()

def main():
    """Main exploit testing routine"""
    print("="*60)
    print("SymbolicHunter - Exploit PoC Script")
    print("="*60)
    print()

'''

        # Add each exploit candidate
        for idx, exploit in enumerate(self.exploit_candidates[:10], 1):
            poc_script += f'''    # Exploit {idx}: {exploit['target_function']}
    test_exploit(
        exploit_name="{exploit['target_function']}",
        input_data=bytes.fromhex("{exploit['input'].hex()}"),
        description="{exploit['description']}"
    )

'''

        poc_script += '''    print("[*] All exploit tests completed")

if __name__ == '__main__':
    main()
'''

        with open(output_file, 'w') as f:
            f.write(poc_script)

        # Make executable on Unix
        import os
        import stat
        os.chmod(output_file, os.stat(output_file).st_mode | stat.S_IEXEC)

        print(f"{Colors.GREEN}[+] PoC script generated: {output_file}{Colors.END}")
        print(f"    Run with: python3 {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='SymbolicHunter - Comprehensive symbolic execution analysis tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s vulnerable_binary
  %(prog)s -v --max-states 2000 binary
  %(prog)s --timeout 600 --output results.json binary
        """
    )

    parser.add_argument('binary', nargs='?', help='Path to the binary to analyze')
    parser.add_argument('extra_binary', nargs='?', help=argparse.SUPPRESS)
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('--max-states', type=int, default=1000,
                       help='Maximum number of states to explore (default: 1000)')
    parser.add_argument('--timeout', type=int, default=300,
                       help='Analysis timeout in seconds (default: 300)')
    parser.add_argument('-o', '--output', help='Export results to JSON file')
    parser.add_argument('--poc', help='Generate PoC exploit script')
    parser.add_argument('--find-function', help='Find paths to specific function (by name)')

    args = parser.parse_args()

    # Handle the case where binary might be in extra_binary due to flags
    if args.extra_binary and not args.binary:
        args.binary = args.extra_binary
    elif args.extra_binary and args.binary:
        # User likely put flags after binary name
        args.binary = args.extra_binary

    if not args.binary:
        parser.error("binary path is required")
        sys.exit(1)

    # Create hunter instance
    hunter = SymbolicHunter(
        args.binary,
        verbose=args.verbose,
        max_states=args.max_states,
        timeout=args.timeout
    )

    # Print header
    hunter.print_header()

    # Run analysis
    hunter.explore_binary(target_function=args.find_function)

    # Print results
    hunter.print_results()

    # Export if requested
    if args.output:
        hunter.export_results(args.output)

    # Generate PoC if requested
    if args.poc:
        hunter.generate_poc_script(args.poc)

    # Summary
    print(f"\n{Colors.BOLD}{Colors.CYAN}╔════════════════════════════════════════════════════════╗")
    print(f"║              SYMBOLIC HUNTER SUMMARY                   ║")
    print(f"╚════════════════════════════════════════════════════════╝{Colors.END}")

    total_vulns = sum(len(v) for v in hunter.vulnerabilities.values())

    # Risk assessment
    risk_level = "LOW"
    risk_color = Colors.GREEN

    if hunter.taint_sinks:
        # Taint sinks are CRITICAL - direct path from input to dangerous function
        risk_level = "CRITICAL"
        risk_color = Colors.RED
    elif hunter.anti_analysis_detected or hunter.unconstrained_paths:
        risk_level = "CRITICAL"
        risk_color = Colors.RED
    elif len(hunter.exploit_candidates) > 0 or total_vulns > 100:
        risk_level = "HIGH"
        risk_color = Colors.RED
    elif total_vulns > 10:
        risk_level = "MEDIUM"
        risk_color = Colors.YELLOW

    print(f"\n{Colors.BOLD}Binary: {Colors.END}{args.binary}")
    print(f"{Colors.BOLD}Risk Level: {risk_color}{risk_level}{Colors.END}")
    print(f"{Colors.BOLD}Analysis Time: {Colors.END}{hunter.stats['time_elapsed']:.2f}s")

    print(f"\n{Colors.BOLD}Key Findings:{Colors.END}")

    if total_vulns > 0:
        print(f"  {Colors.RED}⚠ {Colors.END} {total_vulns} potential security issues ({len(hunter.unique_vulns)} unique)")
    else:
        print(f"  {Colors.GREEN}✓{Colors.END} No obvious vulnerabilities detected")

    if hunter.exploit_candidates:
        print(f"  {Colors.MAGENTA}🎯{Colors.END} {len(hunter.exploit_candidates)} exploit candidates generated")

    if hunter.anti_analysis_detected:
        print(f"  {Colors.RED}🛡 {Colors.END} Anti-analysis techniques detected ({len(hunter.anti_analysis_detected)})")

    if hunter.taint_sinks:
        print(f"  {Colors.RED}💉{Colors.END} {len(hunter.taint_sinks)} tainted data flows to dangerous sinks")

    if hunter.data_flows:
        print(f"  {Colors.CYAN}🔄{Colors.END} {len(hunter.data_flows)} input→output data flows tracked")

    if hunter.dangerous_functions:
        critical_apis = [f for f in hunter.dangerous_functions if f.get('category') in ['process', 'memory', 'library']]
        print(f"  {Colors.YELLOW}⚡{Colors.END} {len(critical_apis)} critical API calls found")

    if hunter.stats['code_coverage'] > 0:
        coverage_icon = "✓" if hunter.stats['code_coverage'] > 50 else "⚠"
        print(f"  {Colors.CYAN}{coverage_icon}{Colors.END} Code coverage: {hunter.stats['code_coverage']:.1f}%")

    # Recommendations
    print(f"\n{Colors.BOLD}Recommendations:{Colors.END}")

    if hunter.taint_sinks:
        print(f"  • {Colors.RED}CRITICAL: Tainted data reaches dangerous functions!{Colors.END}")
        print(f"  • Verify all {len(hunter.taint_sinks)} taint sinks manually")
        print(f"  • Test exploit inputs in isolated environment")

    if risk_level in ["CRITICAL", "HIGH"]:
        print(f"  • {Colors.RED}Immediate manual review required{Colors.END}")
        print(f"  • Run in isolated sandbox environment")
        if hunter.exploit_candidates:
            print(f"  • Test exploit candidates in controlled setting")

    if hunter.anti_analysis_detected:
        print(f"  • {Colors.YELLOW}Binary may evade standard analysis tools{Colors.END}")
        print(f"  • Consider advanced anti-evasion techniques")

    if hunter.data_flows:
        print(f"  • Review {len(hunter.data_flows)} data flow paths for sensitive data leaks")

    if args.output:
        print(f"  • Review detailed JSON report: {args.output}")

    if args.poc:
        print(f"  • Test PoC exploits: python3 {args.poc}")

    if not args.output and not args.poc and (risk_level != "LOW" or hunter.taint_sinks):
        print(f"  • {Colors.CYAN}Tip: Use --output and --poc flags for detailed analysis{Colors.END}")

    print()

    # Exit with appropriate code
    sys.exit(0 if total_vulns == 0 else 1)


if __name__ == '__main__':
    main()
