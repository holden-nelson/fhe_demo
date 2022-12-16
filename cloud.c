#include <tfhe/tfhe.h>
#include <tfhe/tfhe_io.h>
#include <stdio.h>
#include <time.h>

// This file is amended from
// https://tfhe.github.io/tfhe/tuto-cloud.html

void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk);
void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk);

int main() {
    
    //reads the cloud key from file
    FILE* cloud_key = fopen("cloud.key","rb");
    TFheGateBootstrappingCloudKeySet* bk = new_tfheGateBootstrappingCloudKeySet_fromFile(cloud_key);
    fclose(cloud_key);
 
    //if necessary, the params are inside the key
    const TFheGateBootstrappingParameterSet* params = bk->params;

    //containers for the 2x32 ciphertexts
    LweSample* ciphertexts[10];
    for(int i = 0; i < 10; i++)
        ciphertexts[i] = new_gate_bootstrapping_ciphertext_array(32, params);

    //reads the 10x32 ciphertexts from the cloud file
    FILE* cloud_data = fopen("cloud.data","rb");
    for (int i = 0; i < 10; i++)
        for (int j = 0; j < 32; j++)
            import_gate_bootstrapping_ciphertext_fromFile(cloud_data, &ciphertexts[i][j], params);

    fclose(cloud_data);

    //do some operations on the ciphertexts: here, we will compute the
    //minimum of the ten
	printf("Finding minimum.\n");
	clock_t start, end;
	double execution_time;
	start = clock();

    LweSample* result = new_gate_bootstrapping_ciphertext_array(32, params);
    minimum(result, ciphertexts[0], ciphertexts[1], 32, bk);
    printf("*");
    fflush(stdout);

    for (int i = 2; i < 10; i++)
    {
        minimum(result, result, ciphertexts[i], 32, bk);
        printf("*");
        fflush(stdout);
    }

    end = clock();
    execution_time = ( (double)(end-start) )/CLOCKS_PER_SEC;
    printf("\nFound. Took %f seconds.\n", execution_time);

    //export the 1x32 result ciphertext to a file (for the cloud)
    FILE* answer_data = fopen("answer.data","wb");
    for (int i = 0; i < 32; i++) 
        export_gate_bootstrapping_ciphertext_toFile(answer_data, &result[i], params);
    fclose(answer_data);

    //clean up all pointers
    for (int i = 0; i < 10; i++)
        delete_gate_bootstrapping_ciphertext_array(32, ciphertexts[i]);

    delete_gate_bootstrapping_ciphertext_array(32, result);
    delete_gate_bootstrapping_cloud_keyset(bk);

}

// elementary full comparator gate that is used to compare the i-th bit:
//   input: ai and bi the i-th bit of a and b
//          lsb_carry: the result of the comparison on the lowest bits
//   algo: if (a==b) return lsb_carry else return a
void compare_bit(LweSample* result, const LweSample* a, const LweSample* b, const LweSample* lsb_carry, LweSample* tmp, const TFheGateBootstrappingCloudKeySet* bk) {
    bootsXNOR(tmp, a, b, bk);
    bootsMUX(result, tmp, lsb_carry, a, bk);
}

// this function compares two multibit words, and puts the max in result
void minimum(LweSample* result, const LweSample* a, const LweSample* b, const int nb_bits, const TFheGateBootstrappingCloudKeySet* bk) {
    LweSample* tmps = new_gate_bootstrapping_ciphertext_array(2, bk->params);
    
    //initialize the carry to 0
    bootsCONSTANT(&tmps[0], 0, bk);
    //run the elementary comparator gate n times
    for (int i=0; i<nb_bits; i++) {
        compare_bit(&tmps[0], &a[i], &b[i], &tmps[0], &tmps[1], bk);
    }
    //tmps[0] is the result of the comparaison: 0 if a is larger, 1 if b is larger
    //select the max and copy it to the result
    for (int i=0; i<nb_bits; i++) {
        bootsMUX(&result[i], &tmps[0], &b[i], &a[i], bk);
    }

    delete_gate_bootstrapping_ciphertext_array(2, tmps);    
}