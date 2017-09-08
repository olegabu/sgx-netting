//
// Created by vytautas on 7/18/17.
//

#ifndef SGX_NETTING_SEMILOCALALGORITHM_H
#define SGX_NETTING_SEMILOCALALGORITHM_H

#include <string>
#include <set>
#include <map>
#include <vector>
#include <cassert>
#include "shared_ptr.h"

#include "NotionalMatrix.h"

class SemiLocalAlgorithm {
public:
    int maxConvergenceAttempts = 10;

    NotionalMatrix compress(const NotionalMatrix& input_matrix){
        int convergenceAttempts = 0;

        value_t before, after;

        NotionalMatrix matrix = input_matrix;

        do {
            before = getConvergence(matrix);

            auto m_list = matrix.members_list();
            value_t sum = 0;
            for(int i=0; i< m_list.size(); i++)
            for(int j=i+1; j < m_list.size(); j++)
            for(int k = j+1; k < m_list.size(); k++){
                auto& a = m_list[i];
                auto& b = m_list[j];
                auto& c = m_list[k];

                value_t vi = matrix(a,b);
                value_t vj = matrix(b,c);
                value_t vk = matrix(c,a);

                value_t m = median(vi,vj,vk);

                matrix.put(a,b, -m);
                matrix.put(b,c, -m);
                matrix.put(c,a, -m);
            }


            after = getConvergence(matrix);
            convergenceAttempts++;
        } while (before != after && convergenceAttempts < maxConvergenceAttempts);

        if (convergenceAttempts == maxConvergenceAttempts) {
            printf("Maximum value of convergence attempts occurred");
        }

        return matrix;
    }

    value_t getConvergence(const NotionalMatrix& matrix) {
        auto m_list = matrix.members_list();
        value_t sum = 0;
        for(int i=0; i< m_list.size(); i++)
            for(int j=i+1; j < m_list.size(); j++) {
                auto& a = m_list[i];
                auto& b = m_list[j];
                sum += matrix(a,b);
            }

        if(matrix.n_trade_pairs() == 0)
            return 0;
        return 2*sum / matrix.n_trade_pairs();
    }

    static value_t median(value_t a, value_t b, value_t c) {
        return max(min(a,b), min(max(a,b), c));
    }
};




#endif //SGX_NETTING_SEMILOCALALGORITHM_H
