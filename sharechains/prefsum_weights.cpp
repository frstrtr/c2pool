#include "prefsum_weights.h"
#include "tracker.h"

namespace shares::weight
{

//	weight_element_ptr weight_element::operator+(weight_element_ptr element)
//	{
//		this->prev = element;
//		return shared_from_this();
//	}

	weight_element_ptr weight_element::operator+=(const weight_element_ptr &element)
	{
		prev = element;
		return shared_from_this();
	}

//	weight_element_ptr weight_element::operator-(weight_element_ptr element)
//	{
//		if (this->prev != element)
//		{
//			//TODO: assert/debug_error
//		}
//
//		this->prev = nullptr;
//		return element;
//	}


	weight_element_ptr weight_element::operator-=(const weight_element_ptr &element)
	{
		if (this->prev != element)
		{
			//TODO: assert/debug_error
		}

		this->prev = nullptr;
		return shared_from_this();
	}
}
//
//namespace shares::weight
//{
//    PrefsumWeights::PrefsumWeights(std::shared_ptr<ShareTracker> tracker) : _tracker(tracker)
//    {
//        tracker->removed.subscribe([&](ShareType share){
////TODO:            remove(share);
//        });
//    }
//}