use std::cmp::Ordering;

pub type Comparator = fn(&str, &str) -> Ordering;

pub trait ArraySorter {
    fn sort(self, array: &mut [String])
    where
        Self: Sized,
    {
        self.sort_with_comparator(array, |a, b| a.cmp(b))
    }
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized;
}

pub struct BubbleSort;

impl ArraySorter for BubbleSort {
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized,
    {
        let n = array.len();
        for i in 0..(n - 1) {
            for j in 0..(n - 1 - i) {
                let a = &array[j];
                let b = &array[j + 1];
                if compare(a, b).is_gt() {
                    array.swap(j, j + 1)
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct BubbleSortOptimized;

impl ArraySorter for BubbleSortOptimized {
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized,
    {
        let mut new_len: usize;
        let mut len = array.len();
        loop {
            new_len = 0;
            for i in 1..len {
                let a = &array[i - 1];
                let b = &array[i];
                if compare(a, b).is_gt() {
                    array.swap(i - 1, i);
                    new_len = i;
                }
            }
            if new_len == 0 {
                break;
            }
            len = new_len;
        }
    }
}

pub struct SliceSort;

impl Default for SliceSort {
    fn default() -> Self {
        SliceSort
    }
}

impl ArraySorter for SliceSort {
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized,
    {
        array.sort_by(|a, b| compare(a, b))
    }
}

#[derive(Clone)]
pub struct InsertionSort;

impl ArraySorter for InsertionSort {
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized,
    {
        for i in 1..array.len() {
            let mut j = i;
            while j > 0 && compare(&array[j], &array[j - 1]).is_lt() {
                array.swap(j, j - 1);
                j -= 1;
            }
        }
    }
}

#[derive(Clone)]
pub struct QuickSort;

impl ArraySorter for QuickSort {
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized,
    {
        fn partition(arr: &mut [String], low: isize, high: isize, compare: Comparator) -> isize {
            let pivot = high as usize;
            let mut store_index = low - 1;
            let mut last_index = high;

            loop {
                store_index += 1;

                while compare(&arr[store_index as usize], &arr[pivot]).is_lt() {
                    store_index += 1;
                }
                last_index -= 1;

                while last_index >= 0 && compare(&arr[last_index as usize], &arr[pivot]).is_gt() {
                    last_index -= 1;
                }
                if store_index >= last_index {
                    break;
                } else {
                    arr.swap(store_index as usize, last_index as usize);
                }
            }
            arr.swap(store_index as usize, pivot);
            store_index
        }
        fn _quick_sort(arr: &mut [String], low: isize, high: isize, compare: Comparator) {
            if low < high {
                let p = partition(arr, low, high, compare);
                _quick_sort(arr, low, p - 1, compare);
                _quick_sort(arr, p + 1, high, compare);
            }
        }

        let len = array.len();
        _quick_sort(array, 0, (len - 1) as isize, compare);
    }
}

#[derive(Clone)]
pub struct SelectionSort;

impl ArraySorter for SelectionSort {
    fn sort_with_comparator(self, array: &mut [String], compare: Comparator)
    where
        Self: Sized,
    {
        let n = array.len();
        for i in 0..n - 1 {
            let mut min = i;
            for j in i + 1..n {
                if compare(&array[j], &array[min]).is_lt() {
                    min = j;
                }
            }
            array.swap(min, i);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::Lines;
    use std::time::Instant;

    use log::{debug, info};

    use super::*;

    fn init() {
        let _ = env_logger::builder()
            .is_test(true)
            .filter_level(log::LevelFilter::Info)
            .try_init();
    }

    #[test]
    fn bubble_sort_test() {
        init();

        let mut vec1 = ["dd", "dd", "ss"];
        vec1.sort_unstable();
        let sorted_array: Vec<String> = read_sorted_lines().map(|l| l.to_string()).collect();
        let mut array: Vec<String> = read_lines().map(|l| l.to_string()).collect();

        assert!(
            &sorted_array[..].ne(&array[..]),
            "sorted lines and lines should not be equal!"
        );

        do_sort(
            &mut array,
            BubbleSortOptimized,
            stringify!(BubbleSortOptimized),
        );

        assert_eq!(&sorted_array[..], &array[..]);
    }

    #[test]
    fn slice_sort_test() {
        init();

        let sorted_array: Vec<String> = read_sorted_lines().map(|l| l.to_string()).collect();
        let mut array: Vec<String> = read_lines().map(|l| l.to_string()).collect();

        assert!(
            &sorted_array[..].ne(&array[..]),
            "sorted lines and lines should not be equal!"
        );

        do_sort(&mut array, SliceSort, stringify!(SliceSort));

        assert_eq!(&sorted_array[..], &array[..]);
    }

    #[test]
    fn insertion_sort_test() {
        init();

        let sorted_array: Vec<String> = read_sorted_lines().map(|l| l.to_string()).collect();
        let mut array: Vec<String> = read_lines().map(|l| l.to_string()).collect();

        assert!(
            &sorted_array[..].ne(&array[..]),
            "sorted lines and lines should not be equal!"
        );

        do_sort(&mut array, InsertionSort, stringify!(InsertionSort));

        assert_eq!(&sorted_array[..], &array[..]);
    }

    #[test]
    fn quick_sort_test() {
        init();

        let sorted_array: Vec<String> = read_sorted_lines().map(|l| l.to_string()).collect();
        let mut array: Vec<String> = read_lines().map(|l| l.to_string()).collect();

        assert!(
            &sorted_array[..].ne(&array[..]),
            "sorted lines and lines should not be equal!"
        );

        do_sort(&mut array, QuickSort, stringify!(QuickSort));

        assert_eq!(&sorted_array[..], &array[..]);
    }

    #[test]
    fn selection_test() {
        init();

        let sorted_array: Vec<String> = read_sorted_lines().map(|l| l.to_string()).collect();
        let mut array: Vec<String> = read_lines().map(|l| l.to_string()).collect();

        assert!(
            &sorted_array[..].ne(&array[..]),
            "sorted lines and lines should not be equal!"
        );

        do_sort(&mut array, SelectionSort, stringify!(SelectionSort));

        assert_eq!(&sorted_array[..], &array[..]);
    }

    fn do_sort(array: &mut Vec<String>, sort: impl ArraySorter, algorithm_name: &str) {
        let start = Instant::now();
        debug!("before sort:{:?}", &array[..]);
        sort.sort(&mut array[..]);
        debug!("after sort:{:?}", &array[..]);

        let duration = start.elapsed();
        info!(
            "Sort algorithm: {}, number of elements: {:?}, sort time: {:?}",
            algorithm_name,
            array.len(),
            duration
        );
    }

    fn read_sorted_lines() -> Lines<'static> {
        let sorted_file = include_str!("../../../resources/test/freebsd.sort");
        sorted_file.lines()
    }

    fn read_lines() -> Lines<'static> {
        let file = include_str!("../../../resources/test/freebsd");
        file.lines()
    }
}
