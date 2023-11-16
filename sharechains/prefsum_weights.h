#pragma once
#include <memory>
#include <map>
#include <list>
#include <vector>

#include <btclibs/uint256.h>

#include "share.h"
#include <libcoind/data.h>

class ShareTracker;

namespace shares::weight
{
    // TODO: хранить без умножения на 65535 и лишь в конце вычислений, результат, как сумму, умножать на 65535*n;
    // TODO: Оптимизировать память для amount.
    class weight_data
    {
    public:
        std::map<std::vector<unsigned char>, uint288> amount;
        uint288 total_weight;
        uint288 total_donation_weight;

        weight_data()
        {
            amount = {};
            total_weight = 0;
            total_donation_weight = 0;
        }

        weight_data(const ShareType& share)
        {
            auto att = coind::data::target_to_average_attempts(share->target);

            amount = {{{share->address.begin(), share->address.end()}, att * (65535 - *share->donation)}};
            total_weight = att*65535;
            total_donation_weight = att * (*share->donation);
            LOG_INFO << "NEW WEIGHT: [" << share->hash << "]: att = " << att.GetHex() << "; total_weight = " << total_weight.GetHex() << "; total_donation_weight = " << total_donation_weight.GetHex();
        }

        void operator+=(const weight_data &element)
        {
            for (const auto& el : element.amount)
            {
                if (amount.find(el.first) != amount.end())
                    amount[el.first] += el.second;
                else
                    amount[el.first] = el.second;
            }

            total_weight += element.total_weight;
            total_donation_weight += element.total_donation_weight;
        }

        void operator-=(const weight_data &element)
        {
            for (const auto& el : element.amount)
            {
                //TODO: сделать проверку на существование script в словаре?
                amount[el.first] -= el.second;

                if (amount[el.first].IsNull())
                {
                    amount.erase(el.first);
                }
            }

            total_weight -= element.total_weight;
            total_donation_weight -= element.total_donation_weight;
        }

        friend std::ostream &operator<<(std::ostream &stream, weight_data &v)
        {
            stream << "(weight_data: ";
            stream << "total_weight = " << v.total_weight.GetHex();
            stream << ", total_donation_weight = " << v.total_donation_weight.GetHex();
            stream << ", amount = {";
            for (const auto &am : v.amount)
            {
                stream << "(" << am.first << ": " << am.second.GetHex() << "); ";
            }
            stream << "})";

            return stream;
        }
    };
}