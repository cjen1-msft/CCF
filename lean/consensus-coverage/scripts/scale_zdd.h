// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

namespace scale_zdd
{
  // A family of sets of envelope IDs. 0 is no queues; 1 is {empty queue}.
  // At (v,lo,hi), lo omits v and hi contains the remainders after removing v.
  // Nodes are unique by exact triple equality, not merely equal hashes.
  class Diagram
  {
  public:
    using Id = uint32_t;
    using U64 = uint64_t;

  private:
    static constexpr Id END = std::numeric_limits<Id>::max();

    struct Node
    {
      Id var, lo, hi;
      bool operator==(const Node&) const = default;
    };

    struct Cached
    {
      Id op = END, a = 0, b = 0, result = 0;
    };

    std::vector<Node> nodes{{END, 0, 0}, {END, 0, 0}};
    std::vector<U64> counts{0, 1};
    std::vector<Id> lengths{0, 0};
    std::vector<Id> max_slack{0, 0};
    std::vector<Id> terminals{1};
    std::vector<Id> slots = std::vector<Id>(1024, 0);
    std::vector<Cached> cache = std::vector<Cached>(1 << 18);

    static U64 hash(Id x, Id y, Id z)
    {
      U64 h = (U64(x) * 0x9e3779b185ebca87ULL) ^
        (U64(y) * 0xc2b2ae3d27d4eb4fULL) ^ (U64(z) * 0x165667b19e3779f9ULL);
      return h ^ (h >> 32);
    }

    size_t slot(Node n) const
    {
      const size_t mask = slots.size() - 1;
      auto i = hash(n.var, n.lo, n.hi) & mask;
      while (slots[i] && nodes[slots[i]] != n)
        i = (i + 1) & mask;
      return i;
    }

    Id make(Id var, Id lo, Id hi)
    {
      if (!hi)
        return lo;
      if (nodes.size() * 10 >= slots.size() * 7)
      {
        slots.assign(slots.size() * 2, 0);
        for (size_t i = 2; i < nodes.size(); ++i)
          if (nodes[i].var != END)
            slots[slot(nodes[i])] = static_cast<Id>(i);
      }
      Node n{var, lo, hi};
      auto i = slot(n);
      if (slots[i])
        return slots[i];
      if (
        nodes.size() >= END ||
        std::numeric_limits<U64>::max() - counts[lo] < counts[hi])
        throw std::overflow_error("ZDD ID or cardinality overflow");
      slots[i] = static_cast<Id>(nodes.size());
      nodes.push_back(n);
      counts.push_back(counts[lo] + counts[hi]);
      lengths.push_back(std::max(lengths[lo], 1 + lengths[hi]));
      max_slack.push_back(std::max(max_slack[lo], max_slack[hi]));
      return slots[i];
    }

    Id terminal(Id slack)
    {
      while (terminals.size() <= slack)
      {
        if (nodes.size() >= END)
          throw std::overflow_error("ZDD terminal ID overflow");
        Id s = static_cast<Id>(terminals.size());
        terminals.push_back(static_cast<Id>(nodes.size()));
        nodes.push_back({END, s, 0});
        counts.push_back(1);
        lengths.push_back(0);
        max_slack.push_back(s);
      }
      return terminals[slack];
    }

    template <typename F>
    Id memo(Id op, Id a, Id b, F f)
    {
      auto& c = cache[hash(op, a, b) & (cache.size() - 1)];
      if (c.op == op && c.a == a && c.b == b)
        return c.result;
      auto result = f();
      c = {op, a, b, result};
      return result;
    }

    Id combine(Id op, Id a, Id b)
    {
      if (!b || a == b)
        return a == b && op == 1 ? 0 : a;
      if (!a)
        return op == 0 ? b : 0;
      if (nodes[a].var == END && nodes[b].var == END)
        return op == 0 ? terminal(std::min(nodes[a].lo, nodes[b].lo)) : 0;
      if (!op && a > b)
        std::swap(a, b);
      return memo(op, a, b, [&]() {
        auto x = nodes[a], y = nodes[b];
        auto v = std::min(x.var, y.var);
        Id lo = combine(op, x.var == v ? x.lo : a, y.var == v ? y.lo : b);
        Id hi = combine(op, x.var == v ? x.hi : 0, y.var == v ? y.hi : 0);
        return make(v, lo, hi);
      });
    }

  public:
    std::vector<U64> routes;

    size_t size() const
    {
      return nodes.size();
    }

    U64 count(Id a) const
    {
      return counts[a];
    }

    Id max_length(Id a) const
    {
      return lengths[a];
    }

    void collect(const std::vector<Id*>& roots)
    {
      std::vector<Id> remap(nodes.size(), 0);
      for (auto root : roots)
        remap[*root] = END;
      for (auto a : terminals)
        remap[a] = END;
      for (size_t i = nodes.size(); i-- > 2;)
        if (remap[i] && nodes[i].var != END)
        {
          remap[nodes[i].lo] = END;
          remap[nodes[i].hi] = END;
        }
      remap[0] = 0;
      remap[1] = 1;
      Id live = 2;
      for (size_t i = 2; i < nodes.size(); ++i)
        if (remap[i])
        {
          auto n = nodes[i];
          remap[i] = live;
          nodes[live] =
            n.var == END ? n : Node{n.var, remap[n.lo], remap[n.hi]};
          counts[live] = counts[i];
          lengths[live] = lengths[i];
          max_slack[live++] = max_slack[i];
        }
      for (auto root : roots)
        *root = remap[*root];
      for (auto& a : terminals)
        a = remap[a];
      nodes.resize(live);
      counts.resize(live);
      lengths.resize(live);
      max_slack.resize(live);
      size_t capacity = 1024;
      while (capacity * 7 < size_t(live) * 10)
        capacity *= 2;
      slots.assign(capacity, 0);
      for (Id i = 2; i < live; ++i)
        if (nodes[i].var != END)
          slots[slot(nodes[i])] = i;
      std::fill(cache.begin(), cache.end(), Cached{});
    }

    Id unite(Id a, Id b)
    {
      return combine(0, a, b);
    }

    Id minus(Id a, Id b)
    {
      return combine(1, a, b);
    }

    // A terminal stores the minimum extra slots a path needed above the
    // present queue length. On a step of size delta the new slack is
    // max(0, oldSlack - delta); pointwise union keeps the smaller peak.
    Id shift(Id a, Id removed, Id sent)
    {
      if (!a || removed == sent || (removed < sent && max_slack[a] == 0))
        return a;
      auto x = nodes[a];
      if (x.var == END)
      {
        U64 n = U64(x.lo) + removed;
        return terminal(static_cast<Id>(n - std::min(n, U64(sent))));
      }
      return memo(
        7 + (removed > sent),
        a,
        std::max(removed, sent) - std::min(removed, sent),
        [&]() {
          auto lo = shift(x.lo, removed, sent);
          return make(x.var, lo, shift(x.hi, removed, sent));
        });
    }

    template <typename F>
    void rank_counts(F consume) const
    {
      std::vector<U64> previous(nodes.size(), 0), current(nodes.size(), 0);
      auto limit = *std::max_element(lengths.begin(), lengths.end()) +
        terminals.size() - 1;
      for (size_t rank = 0; rank <= limit; ++rank)
      {
        for (size_t a = 1; a < nodes.size(); ++a)
        {
          auto x = nodes[a];
          current[a] =
            x.var == END ? (rank == x.lo) : current[x.lo] + previous[x.hi];
        }
        consume(rank, current);
        current.swap(previous);
      }
    }

    Id cofactor(Id a, Id v, bool present)
    {
      auto x = nodes[a];
      if (x.var > v)
        return present ? 0 : a;
      if (x.var == v)
        return present ? x.hi : x.lo;
      return memo(2 + present, a, v, [&]() {
        auto lo = cofactor(x.lo, v, present);
        return make(x.var, lo, cofactor(x.hi, v, present));
      });
    }

    // The caller has already excluded sets containing v.
    Id put(Id a, Id v)
    {
      if (!a)
        return 0;
      auto x = nodes[a];
      if (v < x.var)
        return make(v, 0, a);
      if (v == x.var)
        throw std::logic_error("collision in symbolic queue insertion");
      return memo(4, a, v, [&]() {
        auto lo = put(x.lo, v);
        return make(x.var, lo, put(x.hi, v));
      });
    }

    Id at_most(Id a, U64 cap)
    {
      if (cap >= lengths[a])
        return a;
      return memo(5, a, static_cast<Id>(cap), [&]() {
        auto x = nodes[a];
        auto lo = at_most(x.lo, cap);
        return cap ? make(x.var, lo, at_most(x.hi, cap - 1)) : lo;
      });
    }

    Id without_endpoint(Id a, Id bit)
    {
      if (nodes[a].var == END)
        return a;
      return memo(6, a, bit, [&]() {
        auto x = nodes[a];
        auto lo = without_endpoint(x.lo, bit);
        return (routes.at(x.var) >> bit) & 1 ?
          lo :
          make(x.var, lo, without_endpoint(x.hi, bit));
      });
    }

    std::vector<Id> pick(Id a) const
    {
      if (!a)
        throw std::logic_error("empty symbolic witness set");
      std::vector<Id> q;
      while (nodes[a].var != END)
      {
        auto n = nodes[a];
        if (n.lo)
          a = n.lo;
        else
        {
          q.push_back(n.var);
          a = n.hi;
        }
      }
      return q;
    }
  };
}
