package com.synswap.compression.matrix;

import com.opengamma.strata.basics.StandardId;
import com.synswap.model.ClearedTrade;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author Nikita Gorbachevski
 */
class CompressionMatrix {

    private final Map<StandardId, Map<StandardId, BigDecimal>> matrix = new HashMap<>();
    private final List<StandardId> members = new ArrayList<>();

    public CompressionMatrix(List<? extends ClearedTrade> trades) {
        for (ClearedTrade trade : trades) {
            if (!members.contains(trade.getParty())) {
                members.add(trade.getParty());
            }
            if (!members.contains(trade.getCounterparty())) {
                members.add(trade.getCounterparty());
            }
        }

        Map<StandardId, BigDecimal> zerosMap = new HashMap<>();
        for (StandardId id : members) {
            zerosMap.put(id, BigDecimal.ZERO);
        }
        for (StandardId id : members) {
            matrix.put(id, new HashMap<>(zerosMap));
        }

        for (ClearedTrade trade : trades) {
            StandardId party = trade.getParty();
            StandardId counterparty = trade.getCounterparty();
            BigDecimal amount = BigDecimal.valueOf(trade.getValue().getAmount());
            // selling is a positive direction, buying is negative
            // TODO seems that buying should be the positive direction
            if (trade.getBuySell().isBuy()) {
                amount = amount.negate();
            }
            matrix.get(party).merge(counterparty, amount, BigDecimal::add);
            matrix.get(counterparty).merge(party, amount.negate(), BigDecimal::add);
        }
    }

    public BigDecimal get(StandardId party, StandardId counterparty) {
        return matrix.get(party).get(counterparty);
    }

    public BigDecimal get(int i, int j) {
        StandardId si = members.get(i);
        StandardId sj = members.get(j);
        return get(si, sj);
    }

    public BigDecimal put(int i, int j, BigDecimal value) {
        StandardId si = members.get(i);
        StandardId sj = members.get(j);
        return matrix.get(si).put(sj, value);
    }

    public StandardId getByIndex(int i) {
        return members.get(i);
    }

    public int size() {
        return matrix.size();
    }
}