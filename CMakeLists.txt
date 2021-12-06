cmake_minimum_required(VERSION 3.0)
project(Crypto_C C)

set(CMAKE_C_STANDARD 11)

add_executable(powering powering.c)
target_link_libraries(powering m)

add_executable(inverse inverse.c)

add_executable(diffie_hellman diffie_hellman.c)
target_link_libraries(diffie_hellman crypto)

add_executable(al-gamal-sender al_gamal.c)
target_link_libraries(al-gamal-sender crypto)
add_executable(al-gamal-receiver al_gamal.c)
target_link_libraries(al-gamal-receiver crypto)

add_executable(al_gamal-simple al_gamal_simple.c)
target_link_libraries(al_gamal-simple crypto)

add_executable(rsa-sender rsa.c)
target_link_libraries(rsa-sender crypto)
add_executable(rsa-receiver rsa.c)
target_link_libraries(rsa-receiver crypto)
add_executable(rsa-sign rsa-sign.c)
target_link_libraries(rsa-sign crypto)

add_executable(rsa-simple rsa_simple.c)
target_link_libraries(rsa-simple crypto)

add_executable(shamir-sender shamir.c)
add_executable(shamir-receiver shamir.c)
target_link_libraries(shamir-sender crypto)
target_link_libraries(shamir-receiver crypto)

add_executable(shamir_simple shamir_simple.c)
target_link_libraries(shamir_simple crypto)

add_executable(sha256_hash sha256_hash.c)
target_link_libraries(sha256_hash crypto)

add_executable(al_gamal_sign al_gamal_sign.c)
target_link_libraries(al_gamal_sign crypto)

add_executable(baby_step_giant_step baby_step_giant_step.c)
target_link_libraries(baby_step_giant_step crypto)

add_executable(index_calculus index_calculus.c)
target_link_libraries(index_calculus crypto)