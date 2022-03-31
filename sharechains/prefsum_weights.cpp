#include "prefsum_weights.h"
#include "tracker.h"

namespace shares::weight
{
	weight_element_ptr::weight_element_ptr(std::vector<unsigned char> _key, arith_uint256 _value)
	{
		value = std::make_shared<weight_element>(std::make_pair(_key, _value));
	}

	std::shared_ptr<weight_element> weight_element_ptr::operator->()
	{
		return value;
	}

	bool weight_element_ptr::is_null() const
	{
		return value ? true : false;
	}

	weight_element_ptr weight_element::operator+(weight_element_ptr element)
	{
		element->prev = shared_from_this();
		return element;
	}

	weight_element_ptr weight_element::operator+=(const weight_element_ptr &element)
	{
		prev = element;
		return ;
	}
}

namespace shares::weight
{
    PrefsumWeights::PrefsumWeights(std::shared_ptr<ShareTracker> tracker) : _tracker(tracker)
    {
        tracker->removed.subscribe([&](ShareType share){
//TODO:            remove(share);
        });
    }
}