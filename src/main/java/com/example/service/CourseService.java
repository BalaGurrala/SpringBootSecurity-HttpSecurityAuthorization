package com.example.service;

import java.util.List;

import org.springframework.stereotype.Service;

import com.example.entity.Course;
import com.example.repo.CourseRepository;

@Service
public class CourseService {

	private CourseRepository courseRepository;
	
	public CourseService(CourseRepository courseRepository) {
		this.courseRepository = courseRepository;
	}
	public List<Course> getAllCourses() {
		return this.courseRepository.findAll();
	}

	public Course getCourse(Long id) {
		return this.courseRepository.findById(id).get();
	}

	public Course addCourse(Course course) {
		return this.courseRepository.save(course);
	}

	public Course updateCourse(Course course) {
		return this.courseRepository.save(course);
	}

	public Course deleteCourse(Long id) {
		Course course = this.courseRepository.findById(id).get();
		this.courseRepository.deleteById(id);
		return course;
	}

}
