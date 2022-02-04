/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_DELEGATE_H
#define PSP2CLDR_DELEGATE_H

#include <atomic>
#include <functional>
#include <vector>

template <typename FunctorType> class MulticastDelegate
{
  public:
    class Token
    {
      private:
        FunctorType functor;
        std::atomic<bool> m_valid;

      public:
        Token(const FunctorType &in_functor, bool in_valid = true) : functor(in_functor), m_valid(in_valid)
        {
        }
        Token(Token &&other)
        {
            functor.swap(other.functor);
            m_valid = other.m_valid.load();
        }

        ~Token()
        {
        }

        void invalidate()
        {
            m_valid = false;
        }
        bool is_valid() const
        {
            return m_valid;
        }
        explicit operator bool() const
        {
            return m_valid;
        }

        template <typename... Params> void invoke(Params &&...params) const
        {
            functor(std::forward<Params>(params)...);
        }
    };

    Token &add(const FunctorType &functor)
    {
        functions.push_back({functor, true});
        return functions.back();
    }

    template <typename... Params> void broadcast(Params &&...params) const
    {
        for (const auto &token : functions)
        {
            if (token)
            {
                token.invoke(std::forward<Params>(params)...);
            }
        }
    }

  protected:
    std::vector<Token> functions;
};

#endif
