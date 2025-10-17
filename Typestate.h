#ifndef TYPESTATE_H
#define TYPESTATE_H

#include <type_traits>
#include <utility>

namespace Typestate {
// Transitions, initial/final states and valid queries, to encode our FSM.
template <auto StartState, auto EndState, auto FunctionPointer>
struct Transition;

template <auto StartState, auto FunctionPointer> struct FinalTransition;

template <auto StartState, auto FunctionPointer> struct ValidQuery;

template <auto... InitialState> struct InitialStates;

template <typename... Transition> struct Transitions;

template <typename... FinalTransition> struct FinalTransitions;

template <typename... ValidQuery> struct ValidQueries;

#define TYPESTATE_MACRO_END_2(LINE)                                            \
  struct some_improbable_long_function_name##LINE {}
#define TYPESTATE_MACRO_END_1(LINE) TYPESTATE_MACRO_END_2(LINE)
#define TYPESTATE_MACRO_END TYPESTATE_MACRO_END_1(__LINE__)

#define TYPESTATE_START_WRAPPER(WRAPPER_TYPE, WRAPPED_TYPE, STATE_TYPE,        \
                                INITIAL_STATES, TRANSITIONS,                   \
                                FINAL_TRANSITIONS, VALID_QUERIES)              \
  template <STATE_TYPE CurrentState>                                           \
  class WRAPPER_TYPE                                                           \
      : public Typestate::internal::GenericWrapper<                            \
            CurrentState, WRAPPER_TYPE, WRAPPED_TYPE, INITIAL_STATES,          \
            TRANSITIONS, FINAL_TRANSITIONS, VALID_QUERIES> {                   \
  public:                                                                      \
    using Base = Typestate::internal::GenericWrapper<                          \
        CurrentState, WRAPPER_TYPE, WRAPPED_TYPE, INITIAL_STATES, TRANSITIONS, \
        FINAL_TRANSITIONS, VALID_QUERIES>;                                     \
    using Wrapped = WRAPPED_TYPE;                                              \
                                                                               \
  private:                                                                     \
    template <auto, template <auto> typename, typename, typename, typename,    \
              typename, typename>                                              \
    friend class Typestate::internal::GenericWrapper;                          \
    WRAPPER_TYPE(Base &&other) : Base(std::move(other)) {}                                \
                                                                               \
  public:                                                                      \
    WRAPPER_TYPE() : Base(Wrapped{}) {}                                        \
    WRAPPER_TYPE(const WRAPPER_TYPE &) = delete;                               \
    WRAPPER_TYPE &operator=(const WRAPPER_TYPE &) = delete;                    \
    TYPESTATE_MACRO_END

#define TYPESTATE_DECLARE_TRANSITION(name)                                     \
  template <typename... Args> auto name(Args &&...args) && {                   \
    return std::move(*this).template call_transition<&Wrapped::name, Args...>( \
        std::forward<Args>(args)...);                                          \
  }                                                                            \
  TYPESTATE_MACRO_END

#define TYPESTATE_DECLARE_FINAL_TRANSITION(name)                               \
  template <typename... Args> auto name(Args &&...args) && {                   \
    return std::move(*this)                                                    \
        .template call_final_transition<&Wrapped::name, Args...>(              \
            std::forward<Args>(args)...);                                      \
  }                                                                            \
  TYPESTATE_MACRO_END

#define TYPESTATE_DECLARE_QUERY_METHOD(name)                                   \
  template <typename... Args> auto name(Args &&...args) const {                \
    return this->template call_valid_query<&Wrapped::name, Args...>(           \
        std::forward<Args>(args)...);                                          \
  }                                                                            \
  TYPESTATE_MACRO_END

#define TYPESTATE_END_WRAPPER }

namespace internal {
struct NotFound {};

template <auto CurrentState, auto FunctionPointer, typename... Transitions>
struct find_transition_t {
  using type = NotFound;
};

template <auto TransitionEnd, auto CurrentState, auto FunctionPointer,
          typename... Transitions>
struct find_transition_t<
    CurrentState, FunctionPointer,
    Transition<CurrentState, TransitionEnd, FunctionPointer>, Transitions...> {
  using type = Transition<CurrentState, TransitionEnd, FunctionPointer>;
};

template <auto CurrentState, auto FunctionPointer, typename... Transitions>
struct find_transition_t<CurrentState, FunctionPointer,
                         FinalTransition<CurrentState, FunctionPointer>,
                         Transitions...> {
  using type = FinalTransition<CurrentState, FunctionPointer>;
};

template <auto CurrentState, auto FunctionPointer, typename... Transitions>
struct find_transition_t<CurrentState, FunctionPointer,
                         ValidQuery<CurrentState, FunctionPointer>,
                         Transitions...> {
  using type = ValidQuery<CurrentState, FunctionPointer>;
};

template <auto CurrentState, auto FunctionPointer, typename Transition,
          typename... Transitions>
struct find_transition_t<CurrentState, FunctionPointer, Transition,
                         Transitions...> {
  using type = typename find_transition_t<CurrentState, FunctionPointer,
                                          Transitions...>::type;
};

template <auto CurrentState, auto FunctionPointer, typename... FinalTransition>
struct find_transition_t<CurrentState, FunctionPointer,
                         FinalTransitions<FinalTransition...>> {
  using type = typename find_transition_t<CurrentState, FunctionPointer,
                                          FinalTransition...>::type;
};

template <auto CurrentState, auto FunctionPointer, typename... Transition>
struct find_transition_t<CurrentState, FunctionPointer,
                         Transitions<Transition...>> {
  using type = typename find_transition_t<CurrentState, FunctionPointer,
                                          Transition...>::type;
};

template <auto CurrentState, auto FunctionPointer, typename... ValidQuery>
struct find_transition_t<CurrentState, FunctionPointer,
                         ValidQueries<ValidQuery...>> {
  using type = typename find_transition_t<CurrentState, FunctionPointer,
                                          ValidQuery...>::type;
};

template <auto CurrentState, auto FunctionPointer, typename... Transitions>
using find_transition =
    typename find_transition_t<CurrentState, FunctionPointer,
                               Transitions...>::type;

template <typename T> struct return_of_transition_t {
  static_assert(!std::is_same_v<T, NotFound>, "Transition not found");
};

template <auto TransitionEnd, auto CurrentState, auto FunctionPointer>
struct return_of_transition_t<
    Transition<CurrentState, TransitionEnd, FunctionPointer>> {
  static constexpr auto EndState = TransitionEnd;
};

template <typename Transitions, auto CurrentState, auto FunctionPointer>
constexpr auto return_of_transition = return_of_transition_t<
    find_transition<CurrentState, FunctionPointer, Transitions>>::EndState;

template <typename T, typename... Args> struct return_of_final_transition_t {
  static_assert(!std::is_same_v<T, NotFound>, "Final transition not found");
};

template <auto CurrentState, auto FunctionPointer, typename... Args>
struct return_of_final_transition_t<
    FinalTransition<CurrentState, FunctionPointer>, Args...> {
  using type = std::invoke_result_t<decltype(FunctionPointer), Args...>;
};

template <typename FinalTransitions, auto CurrentState, auto FunctionPointer,
          typename... Args>
using return_of_final_transition = typename return_of_final_transition_t<
    find_transition<CurrentState, FunctionPointer, FinalTransitions>,
    Args...>::type;

template <typename T, typename... Args> struct return_of_valid_query_t {
  static_assert(!std::is_same_v<T, NotFound>, "Valid query not found");
};

template <auto CurrentState, auto FunctionPointer, typename... Args>
struct return_of_valid_query_t<ValidQuery<CurrentState, FunctionPointer>,
                               Args...> {
  using type = std::invoke_result_t<decltype(FunctionPointer), Args...>;
};

template <typename ValidQueries, auto CurrentState, auto FunctionPointer,
          typename... Args>
using return_of_valid_query = typename return_of_valid_query_t<
    find_transition<CurrentState, FunctionPointer, ValidQueries>,
    Args...>::type;

template <auto State, typename InitialStates> struct check_initial_state_v {
  static_assert(std::is_same_v<InitialStates, std::false_type>,
                "Wrong format for the initial states");
};

template <auto State, auto... InitialState>
struct check_initial_state_v<State, InitialStates<InitialState...>> {
  static constexpr bool value = ((State == InitialState) || ...);
};

template <class T>
struct is_pointer_to_r_value_member_function : std::false_type {};

template <class R, class T, class... Args>
struct is_pointer_to_r_value_member_function<R (T::*)(Args...) &&>
    : std::true_type {};

template <template <typename...> typename ListType, typename Value>
struct is_correct_list_type : std::false_type {};

template <template <typename...> typename ListType, typename... Elements>
struct is_correct_list_type<ListType, ListType<Elements...>> : std::true_type {
};

template <template <auto...> typename ListType, typename ValueType,
          typename Value>
struct is_correct_value_list_type : std::false_type {};

template <template <auto...> typename ListType, typename ValueType,
          ValueType... Elements>
struct is_correct_value_list_type<ListType, ValueType, ListType<Elements...>>
    : std::true_type {};

template <auto CurrentState, template <auto State> typename Wrapper,
          typename Wrapped, typename InitialStates, typename Transitions,
          typename FinalTransitions, typename ValidQueries>
class GenericWrapper {
  static_assert(
      is_correct_value_list_type<::Typestate::InitialStates,
                                 decltype(CurrentState), InitialStates>::value,
      "The list of initial states should be all of the correct type, "
      "and contained in a Typestate::InitialStates type.");
  static_assert(
      is_correct_list_type<::Typestate::Transitions, Transitions>::value,
      "The list of transitions should be contained in a "
      "Typestate::Transitions type");
  static_assert(is_correct_list_type<::Typestate::FinalTransitions,
                                     FinalTransitions>::value,
                "The list of final transitions should be contained in a "
                "Typestate::FinalTransitions type");
  static_assert(
      is_correct_list_type<::Typestate::ValidQueries, ValidQueries>::value,
      "The list of query methods should be contained in a "
      "Typestate::ValidQueries type");

public:
  template <auto NewState>
  using ThisWrapper =
      GenericWrapper<NewState, Wrapper, Wrapped, InitialStates, Transitions,
                     FinalTransitions, ValidQueries>;

  template <auto FunctionPointer, typename... Args>
  auto call_transition(Args &&...args) && {
    (wrapped_.*FunctionPointer)(std::forward<Args>(args)...);
    constexpr auto target_state =
        return_of_transition<Transitions, CurrentState, FunctionPointer>;
    return Wrapper<target_state>(
        ThisWrapper<target_state>{std::move(wrapped_), true});
  }

  template <auto FunctionPointer, typename... Args>
  auto call_final_transition(Args &&...args) && -> return_of_final_transition<
      FinalTransitions, CurrentState, FunctionPointer, Wrapped, Args...> {
    static_assert(
        is_pointer_to_r_value_member_function<decltype(FunctionPointer)>::value,
        "Final transition functions should consume the object: "
        "add && after the argument list.");
    return (std::move(wrapped_).*FunctionPointer)(std::forward<Args>(args)...);
  }

  template <auto FunctionPointer, typename... Args>
  auto call_valid_query(Args &&...args) const
      -> return_of_valid_query<ValidQueries, CurrentState, FunctionPointer,
                               Wrapped, Args...> {
    return (wrapped_.*FunctionPointer)(std::forward<Args>(args)...);
  }

protected:
  template <auto, template <auto> typename, typename, typename, typename,
            typename, typename>
  friend class GenericWrapper;
  GenericWrapper(Wrapped &&wrapped) : wrapped_(std::move(wrapped)) {
    this->template check_initial_state<CurrentState>();
  }

private:
  GenericWrapper(Wrapped &&wrapped, bool ignore_check)
      : wrapped_(std::move(wrapped)) {}
  template <auto State> void check_initial_state() const {
    static_assert(check_initial_state_v<State, InitialStates>::value,
                  "State is not an initial state");
  }
  Wrapped wrapped_;
};

} // namespace internal
} // namespace Typestate

#endif // TYPESTATE_H
