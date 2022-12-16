#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

// This is an amended example from 
// https://tfhe.github.io/tfhe/tuto-alice.html

uint32_t find_min(uint32_t nums[], int length);

int main() 
{
	// generate a keyset
	const int minimum_lambda = 110;
	TFheGateBootstrappingParameterSet* params = new_default_gate_bootstrapping_parameters(minimum_lambda);

	// generate a random (cloud) key
	uint32_t seed[] = { 208, 276, 4459 };
	tfhe_random_generator_setSeed(seed, 3);
	TFheGateBootstrappingSecretKeySet* key = new_random_gate_bootstrapping_secret_keyset(params);


	// export the secret key for later use
	FILE* secret_key = fopen("secret.key", "wb");
	export_tfheGateBootstrappingSecretKeySet_toFile(secret_key, key);
	fclose(secret_key);

	// export the cloud key to a file
	FILE* cloud_key = fopen("cloud.key","wb");
    export_tfheGateBootstrappingCloudKeySet_toFile(cloud_key, &key->cloud);
    fclose(cloud_key);

    // encrypt the data you want to operate on
    // ten random 32-bit ints between 0 and 4 billion
    srand(time(NULL));
    uint32_t plaintexts[10];
    for (int i = 0; i < 10; i++)
        plaintexts[i] = (uint32_t) (rand() % 4000000000);

    // generate corresponding ciphertexts
    LweSample* ciphertexts[10];
    for (int i = 0; i < 10; i++)
    {
        ciphertexts[i] = new_gate_bootstrapping_ciphertext_array(32, params);
        for (int j = 0; j<32; j++)
            bootsSymEncrypt(&ciphertexts[i][j], (plaintexts[i]>>j)&1, key);
    }

    printf("I will ask the cloud what is the minimum of these numbers:\n");
    for(int i = 0; i < 10; i++)
        printf("%d\n", plaintexts[i]);

    // quick min
    clock_t start, end;
    double execution_time;
    start = clock();

    printf("\nFast unencrypted minimum: %d ", find_min(plaintexts, 10));

    end = clock();
    execution_time = ( (double)(end-start) )/CLOCKS_PER_SEC;
    printf("in %f seconds.\n", execution_time);
    
    //export the 10x32 ciphertexts to a file (for the cloud)
    FILE* cloud_data = fopen("cloud.data","wb");
    for(int i = 0; i < 10; i++)
        for(int j = 0; j < 32; j++)
            export_gate_bootstrapping_ciphertext_toFile(cloud_data, &ciphertexts[i][j], params);

    fclose(cloud_data);

    //clean up pointers
    for(int i = 0; i < 10; i++)
        delete_gate_bootstrapping_ciphertext_array(32, ciphertexts[i]);

    delete_gate_bootstrapping_secret_keyset(key);
    delete_gate_bootstrapping_parameters(params);
}

uint32_t find_min(uint32_t nums[], int length)
{
    uint32_t min = nums[0];
    for (int i = 1; i < length; i++)
        if (nums[i] < min)
            min = nums[i];

    return min;
}


