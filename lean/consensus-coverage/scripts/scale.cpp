// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "scale_zdd.h"

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <lean/lean.h>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{
  using L = lean_object;
  using Id = uint32_t;
  using U64 = uint64_t;
  constexpr Id NIL = std::numeric_limits<Id>::max();
  using Clock = std::chrono::steady_clock;
  extern "C"
  {
    L* ccf_scale_initial(L*);
    L* ccf_scale_start(L*, L*);
    L* ccf_scale_node_key(L*, L*);
    L* ccf_scale_ghost_key(L*, L*);
    L* ccf_scale_env_key(L*);
    L* ccf_scale_source(L*);
    L* ccf_scale_target(L*);
    L* ccf_scale_delivery(L*);
    L* ccf_scale_locals(L*, L*);
    L* ccf_scale_step(L*, L*, L*);
    L* ccf_scale_state(L*, L*);
    L* ccf_scale_read(L*, L*, L*, L*, L*);
    L* ccf_scale_witness(L*, L*, L*, L*, L*);
    L* ccf_scale_case_names(L*);
    L* ccf_scale_wide_columns(L*);
    L* ccf_scale_history_row(L*, L*);
  }

  struct Ref
  {
    L* p;

    explicit Ref(L* p = lean_box(0)) : p(p) {}

    Ref(const Ref& o) : p(o.p)
    {
      lean_inc(p);
    }

    Ref(Ref&& o) noexcept : p(o.p)
    {
      o.p = lean_box(0);
    }

    Ref& operator=(Ref o) noexcept
    {
      std::swap(p, o.p);
      return *this;
    }

    ~Ref()
    {
      lean_dec(p);
    }

    static Ref borrow(L* p)
    {
      lean_inc(p);
      return Ref(p);
    }

    L* operator[](unsigned n) const
    {
      return lean_ctor_get(p, n);
    }
  };

  // Every @[export] trampoline consumes its arguments (unlike @[extern]
  // declarations, Lean does not support borrowed parameters on exports).
  template <auto fn, typename... Args>
  L* call(Args... args)
  {
    (lean_inc(args), ...);
    return fn(args...);
  }

  Id id(size_t n)
  {
    if (n >= NIL)
      throw std::overflow_error("32-bit component or parent ID exhausted");
    return static_cast<Id>(n);
  }

  U64 mix(U64 a)
  {
    a = (a ^ (a >> 30)) * 0xbf58476d1ce4e5b9ULL;
    a = (a ^ (a >> 27)) * 0x94d049bb133111ebULL;
    return a ^ (a >> 31);
  }

  std::string bytes(const Ref& b)
  {
    return {
      reinterpret_cast<char*>(lean_sarray_cptr(b.p)), lean_sarray_size(b.p)};
  }

  struct Pool
  {
    std::unordered_map<std::string, Id> ids;
    std::vector<Ref> values;

    Id add(const Ref& key, Ref value)
    {
      auto [it, fresh] = ids.try_emplace(bytes(key), id(values.size()));
      if (fresh)
        values.push_back(std::move(value));
      return it->second;
    }
  };

  using Queue = std::vector<Id>;

  struct QueueHash
  {
    size_t operator()(const Queue& q) const
    {
      U64 h = 1;
      for (auto x : q)
        h = h * 1000003 + x + 1;
      return mix(h);
    }
  };

  struct Frame
  {
    Id nodes, ghost, queue;
    bool operator==(const Frame&) const = default;

    U64 hash() const
    {
      return mix((U64(nodes) << 32 | ghost) ^ mix(queue));
    }
  };

  // One index per occupied slot. A collision always compares all three
  // interned component IDs. This is exact, not a birthday-bound estimate.
  struct Visited
  {
    std::deque<Frame> frames;
    std::vector<Id> slots = std::vector<Id>(1024, NIL);

    size_t slot(Frame f) const
    {
      auto mask = slots.size() - 1;
      auto i = f.hash() & mask;
      while (slots[i] != NIL && frames[slots[i]] != f)
        i = (i + 1) & mask;
      return i;
    }

    bool insert(Frame f)
    {
      if (frames.size() * 10 >= slots.size() * 7)
      {
        slots.assign(slots.size() * 2, NIL);
        for (size_t i = 0; i < frames.size(); ++i)
          slots[slot(frames[i])] = id(i);
      }
      auto s = slot(f);
      if (slots[s] != NIL)
        return false;
      slots[s] = id(frames.size());
      frames.push_back(f);
      return true;
    }
  };

  struct ProtocolEdge
  {
    Id from, to, removed;
    Ref action;
    Queue sent;
  };

  struct Label
  {
    Id key, family, cases;
  };

  struct Reading
  {
    Id ghost;
    Label label;
  };

  struct ReadKey
  {
    Id edge, ghost;
    U64 probes;
    bool operator==(const ReadKey&) const = default;
  };

  struct ReadHash
  {
    size_t operator()(ReadKey x) const
    {
      return mix((U64(x.edge) << 32 | x.ghost) ^ mix(x.probes));
    }
  };

  struct Arc
  {
    Id edge, queue;
    U64 probes;
  };

  struct Menu
  {
    U64 tag = UINT64_MAX;
    std::vector<Arc> arcs;
  };

  struct Parent
  {
    Id parent, edge;
  };

  struct Names
  {
    std::unordered_map<std::string, Id> ids;
    std::vector<std::string> names;

    Id add(const std::string& s)
    {
      auto [it, fresh] = ids.try_emplace(s, id(names.size()));
      if (fresh)
        names.push_back(s);
      return it->second;
    }
  };

  struct Census
  {
    std::string answers;
    Ref buffer;
    U64 count = 0;
  };

  L* history_job(L* bounds, L* actions, L* unit)
  {
    lean_dec(unit);
    return ccf_scale_history_row(bounds, actions);
  }

  struct Search
  {
    L* b;
    U64 cap, budget, seconds, audit_every, audited = 0;
    U64 audited_known = 0, audited_extra = 0;
    bool ordered_census;
    std::string out, case_out;
    Pool nodes, ghosts, envelopes;
    std::vector<U64> sources, targets;
    std::unordered_map<Queue, Id, QueueHash> queue_ids;
    std::deque<const Queue*> queues;
    std::deque<ProtocolEdge> edges;
    std::unordered_map<Id, std::vector<Id>> locals;
    std::unordered_map<U64, Id> deliveries;
    std::vector<Menu> menus = std::vector<Menu>(1 << 13);
    std::unordered_map<ReadKey, Reading, ReadHash> reads;
    Visited visited;
    std::deque<Parent> parents;
    Names keys, families, case_rows;
    std::unordered_map<U64, Id> case_inputs;
    std::vector<std::string> witnesses;
    std::map<Id, std::set<Id>> family_keys;
    std::vector<Census> census;
    Queue wide_columns;
    std::set<std::pair<Id, Id>> counted_rows;
    std::vector<std::string> case_witness;
    U64 head = 0, steps = 0, fetched = 0, menu_misses = 0, model_calls = 0;
    U64 reader_ns = 0, menu_ns = 0;

    Search(L* b, L* params, L* out, L* cases) :
      b(b),
      cap(lean_unbox(lean_array_uget_borrowed(params, 0)) - U64(1)),
      budget(lean_unbox(lean_array_uget_borrowed(params, 1)) - U64(1)),
      seconds(lean_unbox(lean_array_uget_borrowed(params, 2)) - U64(1)),
      audit_every(lean_unbox(lean_array_uget_borrowed(params, 5))),
      ordered_census(lean_unbox(lean_array_uget_borrowed(params, 6)) != 0),
      out(lean_string_cstr(out)),
      case_out(lean_string_cstr(cases))
    {
      if (lean_unbox(lean_array_uget_borrowed(params, 4)))
      {
        Ref cols(call<ccf_scale_wide_columns>(b));
        for (size_t i = 0; i < lean_array_size(cols.p); ++i)
          wide_columns.push_back(id(lean_unbox(lean_array_uget_borrowed(cols.p, i))));
      }
    }

    Id intern_row(Ref buffer)
    {
      auto ans = bytes(buffer);
      auto ci = case_rows.add(ans);
      if (ci == census.size())
        census.push_back({std::move(ans), std::move(buffer)});
      return ci;
    }

    Id queue(Queue q)
    {
      auto [it, fresh] = queue_ids.try_emplace(std::move(q), id(queues.size()));
      if (fresh)
        queues.push_back(&it->first);
      return it->second;
    }

    Ref state(Id n, Id q)
    {
      Ref arr(lean_mk_empty_array_with_capacity(lean_box(queues[q]->size())));
      for (auto e : *queues[q])
      {
        auto v = envelopes.values[e].p;
        lean_inc(v);
        arr.p = lean_array_push(arr.p, v);
      }
      return Ref(call<ccf_scale_state>(nodes.values[n].p, arr.p));
    }

    Id step(Id n, Ref action, Id removed)
    {
      ++model_calls;
      Ref opt(call<ccf_scale_step>(b, nodes.values[n].p, action.p));
      if (lean_is_scalar(opt.p))
        return NIL;
      L* pair = opt[0];
      auto next = lean_ctor_get(pair, 0), sent = lean_ctor_get(pair, 1);
      auto to =
        nodes.add(Ref(call<ccf_scale_node_key>(b, next)), Ref::borrow(next));
      Queue out;
      for (size_t i = 0; i < lean_array_size(sent); ++i)
      {
        auto e = lean_array_uget_borrowed(sent, i);
        auto ei =
          envelopes.add(Ref(call<ccf_scale_env_key>(e)), Ref::borrow(e));
        if (ei == sources.size())
        {
          Ref source(call<ccf_scale_source>(e)),
            target(call<ccf_scale_target>(e));
          if (
            !lean_is_scalar(source.p) || !lean_is_scalar(target.p) ||
            lean_unbox(source.p) >= 64 || lean_unbox(target.p) >= 64)
            throw std::runtime_error("envelope endpoint exceeds probe mask");
          sources.push_back(U64(1) << lean_unbox(source.p));
          targets.push_back(U64(1) << lean_unbox(target.p));
        }
        out.push_back(ei);
      }
      auto ei = id(edges.size());
      edges.push_back({n, to, removed, std::move(action), std::move(out)});
      return ei;
    }

    Id delivery(Id n, Id e)
    {
      auto [it, fresh] = deliveries.try_emplace(U64(n) << 32 | e, NIL);
      if (fresh)
        it->second =
          step(n, Ref(call<ccf_scale_delivery>(envelopes.values[e].p)), e);
      return it->second;
    }

    const std::vector<Id>& local(Id n)
    {
      auto [it, fresh] = locals.try_emplace(n);
      if (fresh)
      {
        Ref a(call<ccf_scale_locals>(b, nodes.values[n].p));
        for (size_t i = 0; i < lean_array_size(a.p); ++i)
        {
          auto ei = step(n, Ref(lean_array_uget(a.p, i)), NIL);
          if (ei != NIL)
            it->second.push_back(ei);
        }
      }
      return it->second;
    }

    const std::vector<Arc>& menu(Id n, Id qi)
    {
      U64 tag = U64(n) << 32 | qi;
      auto& m = menus[mix(tag) & (menus.size() - 1)];
      if (m.tag == tag)
        return m.arcs;
      auto start = Clock::now();
      ++menu_misses;
      m.tag = tag;
      m.arcs.clear();
      const auto& q = *queues[qi];
      U64 src = 0;
      for (Id e : q)
        src |= sources[e];
      auto add = [&](Id ei) {
        if (ei == NIL)
          return;
        const auto& edge = edges[ei];
        if (q.size() - (edge.removed != NIL) + edge.sent.size() > cap)
          return;
        Queue next = q;
        if (edge.removed != NIL)
          next.erase(std::lower_bound(next.begin(), next.end(), edge.removed));
        for (auto e : edge.sent)
        {
          auto pos = std::lower_bound(next.begin(), next.end(), e);
          if (pos != next.end() && *pos == e)
            return;
          next.insert(pos, e);
        }
        U64 probes = src;
        for (Id e : next)
          probes |= targets[e];
        m.arcs.push_back({ei, queue(std::move(next)), probes});
      };
      for (Id e : q)
        add(delivery(n, e));
      for (Id ei : local(n))
        add(ei);
      menu_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
                   Clock::now() - start)
                   .count();
      return m.arcs;
    }

    Reading read(Frame from, Arc arc)
    {
      ReadKey k{arc.edge, from.ghost, arc.probes};
      auto it = reads.find(k);
      if (it != reads.end())
        return it->second;
      auto start = Clock::now();
      ++fetched;
      const auto& e = edges[arc.edge];
      Ref s = state(from.nodes, from.queue), t = state(e.to, arc.queue);
      Ref opt(call<ccf_scale_read>(
        b, ghosts.values[from.ghost].p, s.p, t.p, e.action.p));
      if (lean_is_scalar(opt.p))
        throw std::runtime_error("incremental reader rejected an enabled edge");
      auto r = opt[0], g = lean_ctor_get(r, 0);
      Id gid = ghosts.add(Ref(call<ccf_scale_ghost_key>(b, g)), Ref::borrow(g));
      auto ki = keys.add(lean_string_cstr(lean_ctor_get(r, 1)));
      auto fi = families.add(lean_string_cstr(lean_ctor_get(r, 2)));
      Id ci = NIL;
      if (!case_out.empty() && (!ordered_census || audit_every))
      {
        auto code = lean_ctor_get(r, 3);
        if (!lean_is_scalar(code) || lean_unbox(code) >= NIL)
          throw std::overflow_error("census context exceeds key width");
        auto [entry, fresh] =
          case_inputs.try_emplace(U64(ki) << 32 | lean_unbox(code), NIL);
        if (fresh)
        {
          auto compute = lean_ctor_get(r, 4);
          lean_inc(compute);
          entry->second = intern_row(Ref(lean_apply_1(compute, lean_box(0))));
        }
        ci = entry->second;
        auto extra = lean_ctor_get(r, 5);
        if (!lean_is_scalar(extra))
        {
          auto fn = lean_ctor_get(extra, 0);
          auto input = census.at(ci).buffer.p;
          lean_inc(fn);
          lean_inc(input);
          ci = intern_row(Ref(lean_apply_1(fn, input)));
        }
      }
      family_keys[fi].insert(ki);
      Reading v{gid, {ki, fi, ci}};
      reads.emplace(k, v);
      reader_ns += std::chrono::duration_cast<std::chrono::nanoseconds>(
                     Clock::now() - start)
                     .count();
      return v;
    }

    Ref actions(const Queue& path)
    {
      Ref arr(lean_mk_empty_array_with_capacity(lean_box(path.size())));
      for (auto i = path.rbegin(); i != path.rend(); ++i)
      {
        auto a = edges[*i].action.p;
        lean_inc(a);
        arr.p = lean_array_push(arr.p, a);
      }
      return arr;
    }

    std::string replay_path(const Queue& path, Label l, Id branch)
    {
      auto arr = actions(path);
      Ref key(lean_mk_string(keys.names[l.key].c_str()));
      Ref family(lean_mk_string(families.names[l.family].c_str()));
      Ref line(
        call<ccf_scale_witness>(b, arr.p, key.p, family.p, lean_box(branch)));
      if (lean_is_scalar(line.p))
        throw std::runtime_error(
          "initialized history replay disagrees on key/family/case: " +
          keys.names[l.key]);
      return lean_string_cstr(line[0]);
    }

    Queue parent_path(Id parent, Id edge)
    {
      Queue path{edge};
      while (parent != 0)
      {
        auto p = parents[parent];
        path.push_back(p.edge);
        parent = p.parent;
      }
      return path;
    }

    std::string replay(Id parent, Id edge, Label l, Id branch)
    {
      return replay_path(parent_path(parent, edge), l, branch);
    }

    template <typename Witness>
    void record(Label l, U64 count, Witness witness)
    {
      if (std::numeric_limits<U64>::max() - steps < count)
        throw std::overflow_error("64-bit edge count overflow");
      steps += count;
      if (l.key == witnesses.size())
        witnesses.push_back(witness(NIL));
      if (l.cases != NIL)
      {
        if (!wide_columns.empty())
          counted_rows.emplace(l.key, l.cases);
        auto& c = census[l.cases];
        if (c.count == 0)
        {
          case_witness.resize(c.answers.size());
          for (size_t i = 0; i < c.answers.size(); ++i)
            if (c.answers[i] == 2 && case_witness[i].empty())
              case_witness[i] = witness(id(i));
        }
        c.count += count;
      }
    }

    void initialize()
    {
      Ref s(call<ccf_scale_initial>(b)), g(call<ccf_scale_start>(b, s.p));
      if (lean_is_scalar(s.p))
        throw std::runtime_error("missing initial state");
      nodes.add(Ref(call<ccf_scale_node_key>(b, s.p)), s);
      ghosts.add(Ref(call<ccf_scale_ghost_key>(b, g.p)), g);
      queue({});
    }

    void check_row(const std::string& actual, Id cases, U64 step, U64 frame)
    {
      const auto& cached = census.at(cases).answers;
      if (actual.size() != cached.size())
        throw std::runtime_error("ordered-history census row width mismatch");
      for (Id i : wide_columns)
        if (!cached.at(i))
          throw std::runtime_error("unknown total coordinate in finite audit");
      for (size_t i = 0; i < actual.size(); ++i)
      {
        if (cached[i] == 0)
        {
          audited_extra += actual[i] != 0;
          continue;
        }
        ++audited_known;
        if (actual[i] != cached[i])
          throw std::runtime_error(
            "ordered-history mismatch on edge " + std::to_string(step) +
            ", frame " + std::to_string(frame) + ", question " +
            std::to_string(i));
      }
      ++audited;
    }

    void run()
    {
      initialize();
      visited.insert({0, 0, 0});
      parents.push_back({NIL, NIL});
      struct Audit
      {
        Ref task;
        U64 step, frame;
        Id cases;
      };
      std::vector<Audit> audits;
      auto check_audits = [&]() {
        for (const auto& job : audits)
        {
          auto row = lean_task_get(job.task.p);
          if (lean_is_scalar(row))
            throw std::runtime_error("ordered-history row replay failed");
          check_row(
            bytes(Ref::borrow(lean_ctor_get(row, 0))),
            job.cases,
            job.step,
            job.frame);
        }
        audits.clear();
        if (audited && audited % 1024 == 0)
          std::cout << "reader audit: " << audited << " matching rows" << std::endl;
      };
      auto start = Clock::now();
      auto expired = [&]() {
        return static_cast<U64>(
                 std::chrono::duration_cast<std::chrono::seconds>(
                   Clock::now() - start)
                   .count()) >= seconds;
      };
      while (head < visited.frames.size() && steps < budget && !expired())
      {
        auto f = visited.frames[head];
        bool complete = true;
        for (auto arc : menu(f.nodes, f.queue))
        {
          if (steps == budget)
          {
            complete = false;
            break;
          }
          auto r = read(f, arc);
          if (ordered_census)
          {
            auto path = actions(parent_path(id(head), arc.edge));
            Ref row(call<ccf_scale_history_row>(b, path.p));
            if (lean_is_scalar(row.p))
              throw std::runtime_error("ordered-history census replay failed");
            auto actual = intern_row(Ref::borrow(row[0]));
            if (audit_every && steps % audit_every == 0)
              check_row(census[actual].answers, r.label.cases, steps, head);
            r.label.cases = actual;
          }
          else if (audit_every && steps % audit_every == 0)
          {
            auto prefix = actions(parent_path(id(head), arc.edge));
            auto fn = lean_alloc_closure(reinterpret_cast<void*>(history_job), 3, 2);
            lean_inc(b);
            lean_closure_set(fn, 0, b);
            lean_closure_set(fn, 1, std::exchange(prefix.p, lean_box(0)));
            audits.push_back({Ref(lean_task_spawn_core(fn, 0, false)), steps, head, r.label.cases});
            // Bound retained ordered paths even when the task pool is small.
            if (audits.size() == 16)
              check_audits();
          }
          record(r.label, 1, [&](Id i) {
            return replay(id(head), arc.edge, r.label, i);
          });
          if (visited.insert({edges[arc.edge].to, r.ghost, arc.queue}))
            parents.push_back({id(head), arc.edge});
        }
        if (!complete)
          break;
        ++head;
        if ((head & ((1 << 20) - 1)) == 0)
          std::cout << "progress: expanded " << head << ", frames "
                    << visited.frames.size() << ", keys " << keys.names.size()
                    << std::endl;
      }
      if (audit_every)
      {
        if (!audits.empty())
          check_audits();
        std::cout << "ordered-history row comparisons: " << audited
                  << "\nknown finite answers checked: " << audited_known
                  << "; additional ordered answers: " << audited_extra << '\n';
      }
      report(visited.frames.size());
    }

    void report(U64 frames)
    {
      std::cout << "frames: " << frames << "; expanded: " << head
                << "; frontier: " << frames - head
                << "; fixpoint: " << (frames == head ? "true" : "false")
                << "\nsteps: " << steps << "; keys: " << witnesses.size()
                << "\nmodel calls: " << model_calls
                << "; nodes: " << nodes.values.size()
                << "; envelopes: " << envelopes.values.size()
                << "; queues: " << queues.size()
                << "; ghost values: " << ghosts.values.size()
                << "; reader misses: " << fetched
                << "; census contexts: " << case_inputs.size()
                << "; menu misses: " << menu_misses
                << "; reader ns: " << reader_ns << "; menu ns: " << menu_ns
                << std::endl;
      std::ofstream file;
      file.exceptions(std::ios::badbit | std::ios::failbit);
      file.open(out);
      file << "key\tdepth\tschedule\tqueue_choices\tprefix_keys\n";
      std::sort(
        witnesses.begin(), witnesses.end(), [](const auto& a, const auto& b) {
          auto ai = a.find('\t'), bi = b.find('\t');
          return ai == bi ? a < b : ai < bi;
        });
      for (const auto& w : witnesses)
        file << w;
      file.close();
      for (const auto& [fi, ks] : family_keys)
      {
        std::cout << "family keys: " << families.names[fi] << " ";
        bool first = true;
        for (Id k : ks)
        {
          std::cout << (first ? "" : ",") << keys.names[k];
          first = false;
        }
        std::cout << '\n';
      }
      if (!case_out.empty())
      {
        if (!wide_columns.empty())
        {
          std::set<std::pair<Id, std::string>> wider;
          for (const auto& [key, ci] : counted_rows)
          {
            std::string bits;
            for (Id i : wide_columns)
            {
              auto a = census.at(ci).answers.at(i);
              if (a != 1 && a != 2)
                throw std::logic_error("unknown coordinate in wider key");
              bits.push_back(a);
            }
            wider.emplace(key, std::move(bits));
          }
          std::cout << "wider projection: " << wider.size() << "; extra coordinates: "
                    << wide_columns.size() << '\n';
        }
        Ref names(call<ccf_scale_case_names>(b));
        file.open(case_out);
        file << "index\tquestion\tknown_true\tknown_"
                "false\tunknown\tkey\tdepth\tschedule\tqueue_choices\tprefix_"
                "keys\n";
        for (size_t i = 0; i < lean_array_size(names.p); ++i)
        {
          std::array<U64, 3> counts{};
          for (const auto& c : census)
            counts.at(c.answers.at(i)) += c.count;
          file << i << '\t'
               << lean_string_cstr(lean_array_uget_borrowed(names.p, i)) << '\t'
               << counts[2] << '\t' << counts[1] << '\t' << counts[0] << '\t';
          file
            << (i < case_witness.size() && !case_witness[i].empty() ?
                  case_witness[i] :
                  "\t\t\t\t\n");
        }
        file.close();
      }
    }
  };

  // Maintain one monotonically growing family of queues per control. A
  // separate counting pass avoids counting a queue twice during saturation.
  struct Symbolic : Search
  {
    Symbolic(L* b, L* params, L* out, L* cases) :
      Search(b, params, out, cases),
      ranked(lean_unbox(lean_array_uget_borrowed(params, 3)) == 2)
    {}

    bool ranked;

    struct Group
    {
      Id nodes, ghost, seen = 0, done = 0;
      bool queued = false;
    };

    scale_zdd::Diagram z;
    std::deque<Group> groups;
    std::unordered_map<U64, Id> group_ids;
    std::map<Id, std::deque<Id>> pending;
    std::unordered_map<U64, Id> successors;
    bool counting = false;
    std::set<Id> required_keys;
    U64 endpoints = 0;
    size_t next_gc = 1 << 20;

    struct RankRoot
    {
      Id root, sent, key;
    };

    std::vector<RankRoot> edge_roots;

    void collect()
    {
      if (z.size() < next_gc)
        return;
      std::vector<Id*> roots;
      for (auto& g : groups)
      {
        roots.push_back(&g.seen);
        roots.push_back(&g.done);
      }
      for (auto& e : edge_roots)
        roots.push_back(&e.root);
      z.collect(roots);
      next_gc = std::max(size_t(1 << 20), 3 * z.size());
    }

    Id group(Id n, Id g)
    {
      auto [it, fresh] =
        group_ids.try_emplace(U64(n) << 32 | g, id(groups.size()));
      if (fresh)
        groups.push_back({n, g});
      return it->second;
    }

    static void insert_message(Queue& q, Id e)
    {
      q.insert(std::lower_bound(q.begin(), q.end(), e), e);
    }

    Reading observe(Id g, Id ei, Id rest, U64 probes)
    {
      auto& from = groups[g];
      const auto& e = edges[ei];
      auto hit = reads.find({ei, from.ghost, probes});
      if (hit != reads.end())
        return hit->second;
      auto pre = z.pick(rest), post = pre;
      if (e.removed != NIL)
        insert_message(pre, e.removed);
      for (Id m : e.sent)
        insert_message(post, m);
      return read(
        {from.nodes, from.ghost, queue(std::move(pre))},
        {ei, queue(std::move(post)), probes});
    }

    void partition(Id g, Id ei, Id rest, U64 known, U64 missing)
    {
      if (!rest)
        return;
      if (!missing)
      {
        auto label = observe(g, ei, rest, known).label;
        if (ranked)
          edge_roots.push_back({rest, id(edges[ei].sent.size()), label.key});
        const auto count = z.count(rest);
        if (UINT64_MAX - steps < count)
          throw std::overflow_error("64-bit edge count overflow");
        steps += count;
        required_keys.insert(label.key);
        family_keys[label.family].insert(label.key);
        if (label.cases != NIL)
        {
          census[label.cases].count += count;
          if (!wide_columns.empty())
            counted_rows.emplace(label.key, label.cases);
        }
        return;
      }
      Id bit = std::countr_zero(missing);
      U64 flag = U64(1) << bit;
      Id absent = z.without_endpoint(rest, bit);
      partition(g, ei, absent, known, missing ^ flag);
      partition(g, ei, z.minus(rest, absent), known | flag, missing ^ flag);
    }

    void action(Id g, Id ei, Id rest)
    {
      if (ei == NIL)
        return;
      const auto& e = edges[ei];
      while (z.routes.size() < sources.size())
      {
        auto j = z.routes.size();
        z.routes.push_back(sources[j] | targets[j]);
        endpoints |= z.routes.back();
      }
      if (e.sent.size() > cap)
        return;
      U64 probes = e.removed == NIL ? 0 : sources[e.removed];
      for (size_t i = 0; i < e.sent.size(); ++i)
      {
        auto m = e.sent[i];
        if (
          std::find(e.sent.begin(), e.sent.begin() + i, m) !=
          e.sent.begin() + i)
          return;
        probes |= targets[m];
        rest = z.cofactor(rest, m, false);
      }
      rest = z.at_most(rest, cap - e.sent.size());
      if (!rest)
        return;
      if (ranked)
        rest = z.shift(rest, e.removed == NIL ? 0 : 1, id(e.sent.size()));
      if (counting)
        return partition(g, ei, rest, probes, endpoints & ~probes);
      auto [it, fresh] = successors.try_emplace(U64(g) << 32 | ei, NIL);
      if (fresh)
      {
        for (Id m : z.pick(rest))
          probes |= z.routes[m];
        auto r = observe(g, ei, rest, probes);
        it->second = group(e.to, r.ghost);
      }
      auto& to = groups[it->second];
      for (Id m : e.sent)
        rest = z.put(rest, m);
      auto next = z.unite(to.seen, rest);
      if (next != to.seen)
      {
        to.seen = next;
        if (!to.queued)
        {
          pending[to.ghost].push_back(it->second);
          to.queued = true;
        }
      }
    }

    void expand(Id g, Id set)
    {
      auto n = groups[g].nodes;
      for (size_t m = 0; m < envelopes.values.size(); ++m)
        if (auto rest = z.cofactor(set, id(m), true))
          action(g, delivery(n, id(m)), rest);
      for (Id ei : local(n))
        action(g, ei, set);
    }

    void recover()
    {
      // Discover shortest initialized paths independently of the worklist
      // order. This prefix is not used to count or discharge any frontier.
      std::set<Id> missing = required_keys;
      std::set<size_t> positive;
      for (const auto& c : census)
        if (c.count)
          for (size_t i = 0; i < c.answers.size(); ++i)
            if (c.answers[i] == 2)
              positive.insert(i);
      if (!positive.empty())
        case_witness.resize(*positive.rbegin() + 1);
      visited.insert({0, 0, 0});
      parents.push_back({NIL, NIL});
      for (size_t i = 0;
           i < visited.frames.size() && (!missing.empty() || !positive.empty());
           ++i)
      {
        auto f = visited.frames[i];
        for (auto arc : menu(f.nodes, f.queue))
        {
          auto r = read(f, arc);
          if (missing.erase(r.label.key))
            witnesses.push_back(replay(id(i), arc.edge, r.label, NIL));
          if (r.label.cases != NIL)
          {
            const auto& answers = census[r.label.cases].answers;
            for (auto j = positive.begin(); j != positive.end();)
              if (answers[*j] == 2)
              {
                case_witness[*j] = replay(id(i), arc.edge, r.label, id(*j));
                j = positive.erase(j);
              }
              else
                ++j;
          }
          if (visited.insert({edges[arc.edge].to, r.ghost, arc.queue}))
            parents.push_back({id(i), arc.edge});
        }
      }
      if (!missing.empty() || !positive.empty())
        throw std::logic_error(
          "no initialized representative for a symbolic observation");
    }

    void run()
    {
      initialize();
      group(0, 0);
      groups[0].seen = 1;
      pending[0].push_back(0);
      groups[0].queued = true;
      auto start = Clock::now();
      size_t iterations = 0;
      while (!pending.empty() &&
             static_cast<U64>(std::chrono::duration_cast<std::chrono::seconds>(
                                Clock::now() - start)
                                .count()) < seconds)
      {
        collect();
        auto it = pending.begin();
        auto g = it->second.front();
        it->second.pop_front();
        if (it->second.empty())
          pending.erase(it);
        auto& group = groups[g];
        group.queued = false;
        group.done = group.seen;
        expand(g, group.done);
        if ((++iterations % 10000) == 0)
          std::cout << "saturation: " << iterations << " group expansions, "
                    << groups.size() << " controls, " << z.size()
                    << " diagram nodes" << std::endl;
      }
      U64 frames = 0;
      Id max_queue = 0;
      counting = true;
      family_keys.clear();
      for (size_t i = 0; i < groups.size(); ++i)
      {
        collect();
        const auto& g = groups[i];
        if (UINT64_MAX - frames < z.count(g.seen))
          throw std::overflow_error("64-bit frame count overflow");
        frames += z.count(g.seen);
        max_queue = std::max(max_queue, z.max_length(g.seen));
        head += z.count(g.done);
        if (g.done)
          expand(id(i), g.done);
      }
      auto counted_families = family_keys;
      recover();
      family_keys = std::move(counted_families);
      std::cout << "Symbolic: exact ZDD cardinalities; elapsed throughput is "
                   "not explicit frames/s.\n";
      std::cout << "maximum reachable queue length in visited set: "
                << max_queue << '\n';
      if (ranked)
      {
        // A queue's minimum admissible cap is its length plus terminal slack;
        // on residual queues in the edge census the sent suffix is also due.
        next_gc = 0;
        collect();
        std::vector<U64> frame_bins(size_t(max_queue) + 1),
          edge_bins(frame_bins.size());
        std::vector<Id> first(keys.names.size(), NIL);
        z.rank_counts([&](size_t rank, const std::vector<U64>& counts) {
          for (const auto& g : groups)
            if (counts[g.seen])
              frame_bins.at(rank) += counts[g.seen];
          for (const auto& e : edge_roots)
            if (counts[e.root])
            {
              size_t k = rank + e.sent;
              edge_bins.at(k) += counts[e.root];
              first.at(e.key) = std::min(first[e.key], id(k));
            }
        });
        U64 f = 0, s = 0;
        size_t ks = 0;
        for (size_t k = 0; k < frame_bins.size(); ++k)
        {
          f += frame_bins[k];
          s += edge_bins[k];
          auto added = std::count(first.begin(), first.end(), k);
          ks += added;
          std::cout << "cap " << k << ": frames " << f << "; edges " << s
                    << "; keys " << ks << "; new " << added << '\n';
          for (size_t j = 0; j < first.size(); ++j)
            if (first[j] == k)
              std::cout << "first cap: " << k << "; key: " << keys.names[j]
                        << '\n';
        }
        if (f != frames || s != steps || ks != required_keys.size())
          throw std::logic_error(
            "ranked counts disagree with unweighted support");
      }
      report(frames);
    }
  };
}

extern "C" L* ccf_scale_run(L* b, L* params, L* out, L* cases)
{
  try
  {
    if (lean_unbox(lean_array_uget_borrowed(params, 3)))
      Symbolic(b, params, out, cases).run();
    else
      Search(b, params, out, cases).run();
    return lean_io_result_mk_ok(lean_box(0));
  }
  catch (const std::exception& e)
  {
    return lean_io_result_mk_error(
      lean_mk_io_user_error(lean_mk_string(e.what())));
  }
}
