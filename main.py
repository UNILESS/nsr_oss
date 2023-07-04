import argparse
import codecs
import multiprocessing
import os
import glob
import time
import traceback
from concurrent.futures.thread import ThreadPoolExecutor
from enum import Enum
import datetime


class QuickBccVerb(Enum):
    None_verb = 0x00
    GenOSS = 0x10
    MatchOSS = 0x20
    Help = 0xF0


class QuickBccOptions:
    def __init__(self):
        self.Verb = QuickBccVerb.None_verb


class GenOSSOptions(QuickBccOptions):
    def __init__(self):
        super().__init__()
        self.OSS = ""
        self.OutputDir = ""
        self.Threads = 0
        self.Verbose = False


class MatchOSSOptions(QuickBccOptions):
    def __init__(self):
        super().__init__()
        self.TargetBin = ""
        self.Threads = 0
        self.OutputDir = ""
        self.Verbose = False
        self.Debug = False
        self.DisableFilter = False


def PrintAndSaveResults(runResult, destDir):
    # Print & save statistics
    log = runResult.result_message()
    print(log)
    print("Saving results...")

    os.makedirs(destDir, exist_ok=True)
    logTextFile = os.path.join(destDir, "log.txt")
    with codecs.open(logTextFile, 'w', 'utf-8') as f:
        f.write(log)

    cacheList = runResult.save_cache_list()
    cacheListFile = os.path.join(destDir, "cache_list.txt")
    with codecs.open(cacheListFile, 'w', 'utf-8') as f:
        f.write(cacheList)

    runResult.SaveResults()

    print("Done!")
    print()


class Program:
    @staticmethod
    def Main(args):
        try:
            start_time = datetime.datetime.now()

            # Parse arguments
            opts = None
            arg_parser = argparse.ArgumentParser()
            subparsers = arg_parser.add_subparsers(dest='command')

            # Add subparsers for each command
            gen_sig_parser = subparsers.add_parser('genoss', help='Generate OSS Signatures')
            gen_sig_parser.add_argument('oss', metavar='oss', help='oss file or directory')
            gen_sig_parser.add_argument('output_dir', metavar='output_dir', help='Output directory')
            gen_sig_parser.add_argument('--threads', metavar='threads', type=int, default=0, help='Number of threads')
            gen_sig_parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
            gen_sig_parser.set_defaults(command='genoss')

            match_vul_parser = subparsers.add_parser('matchoss', help='Match OpenSourceSoftware')
            match_vul_parser.add_argument('target_bin', metavar='target_bin', help='Target binary or directory')
            match_vul_parser.add_argument('--threads', metavar='threads', type=int, default=0, help='Number of threads')
            match_vul_parser.add_argument('--output_dir', metavar='output_dir', help='Output directory')
            match_vul_parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
            match_vul_parser.add_argument('--debug', action='store_true', help='Enable debug output')
            match_vul_parser.add_argument('--disable_filter', action='store_true', help='Disable filtering of matches')
            match_vul_parser.set_defaults(command='matchoss')

            args = arg_parser.parse_args()

            if args.command == 'genoss':
                opts = GenOSSOptions()
                opts.Verb = QuickBccVerb.GenOSS
                opts.OSS = args.oss
                opts.OutputDir = args.output_dir
                opts.Threads = args.threads
                opts.Verbose = args.verbose
            elif args.command == 'matchoss':
                opts = MatchOSSOptions()
                opts.Verb = QuickBccVerb.MatchOSS
                opts.TargetBin = args.target_bin
                opts.Threads = args.threads
                opts.OutputDir = args.output_dir
                opts.Verbose = args.verbose
                opts.Debug = args.debug
                opts.DisableFilter = args.disable_filter

            if opts is None:
                arg_parser.print_help()
                return

            Program.RunCommand(opts)

            end_time = datetime.datetime.now()
            elapsed_time = end_time - start_time
            print(f"Elapsed Time: {elapsed_time}")

        except KeyboardInterrupt:
            print("Interrupted")

    @staticmethod
    def RunCommand(opts):
        if opts.Verb == QuickBccVerb.GenOSS:
            Program.GenOSS(opts)
        elif opts.Verb == QuickBccVerb.MatchOSS:
            Program.match_OSS(opts)
        else:
            print("Invalid command")

    @staticmethod
    def GenOSS(opts):
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        print("Generate OSS Signatures")
        OSS_full_path = os.path.abspath(opts.OSS)
        sig_output_path = os.path.join(opts.OutputDir, now)

        # Look for vulnerability signature json files
        if os.path.isdir(OSS_full_path):
            # Search for sub-directory
            OSS_files = glob.glob(os.path.join(OSS_full_path, ''), recursive=True)  # TODO 확장자 뭘로 받을지
        elif '*' in os.path.basename(OSS_full_path):
            wildcard = os.path.basename(OSS_full_path)
            search_dir = os.path.dirname(OSS_full_path)
            OSS_files = glob.glob(os.path.join(search_dir, wildcard), recursive=True)
            OSS_files = [f for f in OSS_files if f.endswith('')]  # TODO 확장자 뭘로 받을지
        else:
            OSS_files = [OSS_full_path]

        if len(OSS_files) == 0:
            print("No OSS found")
            return
        elif len(OSS_files) == 1:
            print("Generating a OSS signature")
        else:
            print(f"Generating {len(OSS_files)} OSS signatures")

        # Gather markList

        OSS_list = []
        for OSS_path in sorted(OSS_files):
            try:
                if os.path.isdir(OSS_path):
                    # Iterate through the files in the directory
                    for root, dirs, files in os.walk(OSS_path):
                        for file in files:
                            if file.endswith(".so") or file.endswith(".elf"):  # TODO 확장자 고려하고 추가하기
                                binary_file_path = os.path.join(root, file)
                                OSS_list.append(binary_file_path)
                elif os.path.isfile(OSS_path):
                    OSS_list.append(OSS_path)
                else:
                    print(f"Path [{OSS_path}] does not exist")
            except Exception as e:
                print(f"Error processing path [{OSS_path}]: {e}")
                if opts.Verbose:
                    print(f"{e.__class__.__name__}: {e}")
                    print(e.__traceback__)
                continue

            print(f"{OSS_path} - OK")

        # Evaluate thread count
        threads = opts.Threads
        cpu_threads = multiprocessing.cpu_count()
        if threads <= 0:
            threads = multiprocessing.cpu_count()

        # Create strands in parallel
        print(f"Using [{threads}] threads (CPU {cpu_threads}t)")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            for OSS in OSS_list:
                # OSS Binary
                OSS_fisrt_gen = StrandGenerator(OSS, None, opts.Verbose, False)
                OSS_second_gen = StrandGenerator(OSS, None, opts.Verbose, False)

                try:
                    for gen in [OSS_fisrt_gen, OSS_second_gen]:
                        if gen is not None:
                            gen.gen_strand_py_vex(False, False)

                    OSS_fisrt_gen.save_signature(OSS, sig_output_path)
                except Exception as e:
                    traceback.print_exc()  # 스레드 에러 메시지 출력
                finally:
                    OSS_fisrt_gen.cleanup_dest_dir()
                    if OSS_second_gen is not None:
                        OSS_second_gen.cleanup_dest_dir()

    @staticmethod
    def match_OSS(opts):
        start_time = time.time()
        now = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        # Get a list of target files
        target_bins, base_dir, target_arches = Matcher.get_target_files(opts.TargetBin, opts.DisableFilter)

        # Sort the target bins
        target_bins.sort()

        # Load OSS Signature
        bcc_sign_dict = {}
        for arch in target_arches:
            rows = session.query(Signature).filter(Signature.arch == arch.value).all()
            bcc_sign_dict[int(arch.value)] = [BccSignature(row) for row in rows]

        print(f"[{sum(len(signatures) for signatures in bcc_sign_dict.values())}] signatures loaded")
        load_time_span = datetime.timedelta(seconds=(time.time() - start_time))

        # Evaluate thread count
        threads = opts.Threads
        cpu_threads = multiprocessing.cpu_count()
        if threads <= 0:
            threads = cpu_threads
        print(f"Using [{threads}] threads (CPU {cpu_threads}t)")

        # Prepare statistics
        dest_dir = os.path.join(opts.OutputDir, now)
        run_result = RunResult(base_dir, dest_dir, len(target_bins))
        run_result.threads_count = threads
        run_result.actual_load_time = load_time_span

        # Actual Match
        Matcher.match_multiple_targets(run_result, base_dir, threads, target_bins, bcc_sign_dict,
                                       opts.DisableFilter, opts.Verbose, opts.Debug)
        run_result.save_sign_arch_stat(bcc_sign_dict)
        PrintAndSaveResults(run_result, dest_dir)

        execution_time = datetime.timedelta(seconds=(time.time() - start_time))
        print(f"Execution time: {execution_time}")


if __name__ == '__main__':
    Program.Main(None)
