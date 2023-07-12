import os
import pickle
import hashlib
import argparse


def calculate_hash(filename):
    with open(filename, 'rb') as file:
        data = file.read()
        return hashlib.md5(data).hexdigest()


def compare_directories(directory_a, directory_b, threshold, verbose):
    files_a = [file for file in os.listdir(directory_a) if file.endswith('.pickle')]
    files_b = [file for file in os.listdir(directory_b) if file.endswith('.pickle')]

    print(f"Comparing files in {directory_a} and {directory_b} directories...")
    print("===============================================")

    for file_a in files_a:
        hash_a = calculate_hash(os.path.join(directory_a, file_a))
        print(f"Processing file: {file_a}")

        for file_b in files_b:
            hash_b = calculate_hash(os.path.join(directory_b, file_b))
            similarity_score = sum(a == b for a, b in zip(hash_a, hash_b)) / len(hash_a)

            if verbose:
                print(f"Similarity Score ({file_a}, {file_b}): {similarity_score}")
            elif similarity_score >= threshold:
                print(f"Similar files found:")
                print(f"{file_a} in {directory_a}")
                print(f"{file_b} in {directory_b}")
                print(f"Similarity Score: {similarity_score}")
                print("-----------------------------------------------")

    print("===============================================")
    print("Comparison completed.")


# A 디렉토리와 B 디렉토리의 경로 설정
directory_a = 'output/openssl_1_0_1f_gcc-4.9.4_arm_32_O0'
directory_b = 'output/openssl_sig'

# 유사도의 일정 범위 설정
threshold = 0.3

# 명령줄 인자 파싱을 위한 ArgumentParser 생성
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose mode to display similarity scores for all files")
args = parser.parse_args()

compare_directories(directory_a, directory_b, threshold, args.verbose)
