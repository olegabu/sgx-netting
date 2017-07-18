package com.synswap.compression.matrix;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.math.BigDecimal;

/**
 * @author Nikita Gorbachevski
 */
public class SemiLocalCompressionAlgorithm implements CompressionAlgorithm {

    private static final Log log = LogFactory.getLog(SemiLocalCompressionAlgorithm.class);
    private static final int DEFAULT_MAX_CONVERGENCE_ATTEMPTS = 10;

    private final int maxConvergenceAttempts;

    public SemiLocalCompressionAlgorithm() {
        this.maxConvergenceAttempts = DEFAULT_MAX_CONVERGENCE_ATTEMPTS;
    }

    public SemiLocalCompressionAlgorithm(int maxConvergenceAttempts) {
        this.maxConvergenceAttempts = maxConvergenceAttempts;
    }

    @Override
    public CompressionMatrix compress(CompressionMatrix matrix) {
        int convergenceAttempts = 0;
        BigDecimal before;
        BigDecimal after;
        do {
            before = getConvergenceValue(matrix);
            for (int i = 0; i < matrix.size(); i++) {
                for (int j = i + 1; j < matrix.size(); j++) {
                    for (int k = j + 1; k < matrix.size(); k++) {
                        BigDecimal vi = matrix.get(i, j);
                        BigDecimal vj = matrix.get(j, k);
                        BigDecimal vk = matrix.get(k, i);

                        BigDecimal compressionValue = getCompressionValue(vi, vj, vk);

                        matrix.put(i, j, vi.subtract(compressionValue));
                        matrix.put(j, k, vj.subtract(compressionValue));
                        matrix.put(k, i, vk.subtract(compressionValue));

                        matrix.put(j, i, compressionValue.subtract(vi));
                        matrix.put(k, j, compressionValue.subtract(vj));
                        matrix.put(i, k, compressionValue.subtract(vk));
                    }
                }
            }
            after = getConvergenceValue(matrix);
            convergenceAttempts++;
        } while (!before.equals(after) && convergenceAttempts < maxConvergenceAttempts);

        if (convergenceAttempts == maxConvergenceAttempts) {
            log.warn("Maximum value of convergence attempts occurred");
        }

        return matrix;
    }

    private BigDecimal getConvergenceValue(CompressionMatrix compressionMatrix) {
        int size = compressionMatrix.size();
        BigDecimal sum = BigDecimal.ZERO;
        BigDecimal m = new BigDecimal(size);
        for (int i = 0; i < size; i++) {
            for (int j = i + 1; j < size; j++) {
                BigDecimal val = compressionMatrix.get(i, j);
                sum = sum.add(val.abs());
            }
        }
        // division by zero?
        return new BigDecimal(2).divide(
                m.multiply(m.subtract(BigDecimal.ONE)), 10, BigDecimal.ROUND_HALF_DOWN)
                .multiply(sum)
                .setScale(2, BigDecimal.ROUND_HALF_DOWN);
    }

    private BigDecimal getCompressionValue(BigDecimal v1, BigDecimal v2, BigDecimal v3) {
        // math median
        return max(min(v1, v2), min(max(v1, v2), v3));
    }

    private BigDecimal min(BigDecimal a, BigDecimal b) {
        return a.compareTo(b) <= 0 ? a : b;
    }

    private BigDecimal max(BigDecimal a, BigDecimal b) {
        return a.compareTo(b) >= 0 ? a : b;
    }
}
